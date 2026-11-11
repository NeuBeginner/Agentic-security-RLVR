"""The single dispatch path of the evidence-regeneration workflow (plan D27).

The dispatch helper is the only path through which this workflow dispatches a Modal
call. It enforces, per step:

1. an **invocation budget** per container class - at most ``invocations(c)`` dispatches
   of class ``c``; the next one is refused and the refusal is recorded;
2. a **concurrency gate** per container class - at most ``cap(c)`` dispatches of class
   ``c`` in flight at the same time;
3. a **ceiling assertion** - ``cap(c) <= max_containers_deployed(c)``; if the step's
   approved cap exceeds the deployed ceiling the step is refused as
   "deployed ceiling too low";
4. the **completeness of the declared bounds** - while a required bound of the class is
   required-but-unset, no dispatch of that class happens (fail closed);
5. the **producer-enforced payload cap** of the volume-writing functions (D28);
6. the **egress declaration** of the dispatched function (D29);
7. the **autoscaler read-back** before the first container of the step - the
   no-argument ``update_autoscaler()`` call, which changes nothing and returns the
   effective settings. There is no mutating autoscaler call in this repository.

A dispatch of a *real provider callable* additionally requires an approved step
policy. A local double (a test double) is passed through, because it starts no
container and costs nothing.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

from core.r1_bounds import (
    Bound,
    FUNCTION_CLASS,
    Unset,
    assert_payload_within_cap,
    egress_policy,
    is_provider_callable,
    is_unset,
    profile_for,
)

#: The functions that write to the persistent volume and are therefore capped (D28).
VOLUME_WRITING_FUNCTIONS = frozenset({"record_trajectory_remote"})


class DispatchRefusal(RuntimeError):
    """A refused dispatch, with the machine-readable reason that caused it."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        message = f"dispatch refused: {reason}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


@dataclass(frozen=True)
class StepPolicy:
    """The approval record of one compute step.

    The cap table is part of the approval record, not a runtime parameter: raising a
    per-step cap is a change to the approval record and needs a new approval.
    """

    step_id: str
    invocation_budgets: Dict[str, int]
    concurrency_caps: Dict[str, int]
    wall_clock_budget_sec: Bound
    post_execution_deadline_sec: Bound
    monetary_ceiling_usd: Bound
    estimate_usd: Optional[float]
    approved_by: str
    approved_at: str

    def missing_fields(self) -> List[str]:
        """The fields of the policy that are required-but-unset (D28, Q5)."""
        missing: List[str] = []
        if is_unset(self.wall_clock_budget_sec):
            missing.append("wall_clock_budget_sec")
        if is_unset(self.post_execution_deadline_sec):
            missing.append("post_execution_deadline_sec")
        if is_unset(self.monetary_ceiling_usd):
            missing.append("monetary_ceiling_usd")
        if self.estimate_usd is None:
            missing.append("estimate_usd")
        for container_class in FUNCTION_CLASS.values():
            if container_class not in self.invocation_budgets:
                missing.append(f"invocation_budgets[{container_class}]")
            if container_class not in self.concurrency_caps:
                missing.append(f"concurrency_caps[{container_class}]")
        return missing

    def validate(self) -> None:
        missing = self.missing_fields()
        if missing:
            raise DispatchRefusal("policy_incomplete", ", ".join(missing))
        if self.estimate_usd is not None and float(self.estimate_usd) > float(self.monetary_ceiling_usd):  # type: ignore[arg-type]
            raise DispatchRefusal(
                "estimate_above_ceiling",
                f"estimate {self.estimate_usd} > ceiling {self.monetary_ceiling_usd}",
            )


def read_back_autoscaler(target: Any) -> Dict[str, Any]:
    """Read the effective autoscaler settings **without mutating them**.

    The pinned SDK (1.5.5) has no ``Function.autoscaler`` namespace, so the read-back
    is the **no-argument** call ``update_autoscaler()``. Its own documentation states
    that "Unspecified parameters will retain their current value, i.e. either the
    static value from the function decorator, or an override value from a previous
    call to this method" - a call with no argument therefore changes nothing and
    returns the current settings.

    If the SDK provides no read-back at all, the step is not dispatchable: an
    unverifiable cap is an unbounded one.
    """
    updater = getattr(target, "update_autoscaler", None)
    if updater is None:
        raise DispatchRefusal(
            "autoscaler_readback_unavailable",
            f"{type(target).__name__} exposes no update_autoscaler()",
        )
    settings = updater()  # no arguments: this call never mutates the settings
    return {
        "min_containers": getattr(settings, "min_containers", None),
        "max_containers": getattr(settings, "max_containers", None),
        "buffer_containers": getattr(settings, "buffer_containers", None),
        "scaledown_window": getattr(settings, "scaledown_window", None),
    }


@dataclass
class DispatchRecord:
    step_id: str
    container_class: str
    function_name: str
    outcome: str
    reason: str = ""
    detail: str = ""
    provider_callable: bool = False
    at: float = 0.0

    def to_record(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "container_class": self.container_class,
            "function_name": self.function_name,
            "outcome": self.outcome,
            "reason": self.reason,
            "detail": self.detail,
            "provider_callable": self.provider_callable,
        }


class DispatchGate:
    """Enforces the per-step dispatch contract of one approved step."""

    def __init__(
        self,
        policy: Optional[StepPolicy] = None,
        profiles: Optional[Dict[str, Any]] = None,
        egress_policies: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.policy = policy
        self.profiles = profiles or {}
        self.egress_policies = egress_policies or {}
        self.records: List[DispatchRecord] = []
        self.used: Dict[str, int] = {}
        self._semaphores: Dict[str, threading.BoundedSemaphore] = {}
        self._readback_done: Dict[str, bool] = {}
        self._started_at = time.monotonic()
        self._lock = threading.Lock()

    # -- helpers ------------------------------------------------------------------

    def _profile(self, container_class: str) -> Any:
        return self.profiles.get(container_class) or profile_for(container_class)

    def _egress(self, function_name: str) -> Any:
        from core.r1_bounds import egress_policy as _declared_egress_policy

        return self.egress_policies.get(function_name) or _declared_egress_policy(function_name)

    def _semaphore(self, container_class: str) -> threading.BoundedSemaphore:
        if container_class not in self._semaphores:
            cap = 1
            if self.policy is not None:
                cap = max(1, int(self.policy.concurrency_caps.get(container_class, 1)))
            self._semaphores[container_class] = threading.BoundedSemaphore(cap)
        return self._semaphores[container_class]

    def _refuse(self, container_class: str, function_name: str, reason: str, detail: str = "") -> None:
        record = DispatchRecord(
            step_id=self.policy.step_id if self.policy else "<no-policy>",
            container_class=container_class,
            function_name=function_name,
            outcome="refused",
            reason=reason,
            detail=detail,
            provider_callable=True,
            at=time.time(),
        )
        self.records.append(record)
        raise DispatchRefusal(reason, detail)

    # -- the dispatch path ---------------------------------------------------------

    def dispatch(
        self,
        container_class: str,
        function_name: str,
        fn: Any,
        *args: Any,
        readback_target: Any = None,
        **kwargs: Any,
    ) -> Any:
        """Dispatch one call of ``function_name`` under the step's contract.

        Returns whatever the call returns. Raises :class:`DispatchRefusal` when the
        dispatch is not allowed; the refusal is recorded first.
        """
        provider_callable = is_provider_callable(fn)

        if provider_callable:
            self._check_policy(container_class, function_name)
            self._check_bounds(container_class, function_name)
            self._check_egress(function_name)
            self._check_ceiling(container_class, function_name)
            self._check_budget(container_class, function_name)
            self._check_payload_cap(function_name, args)
            self._check_readback(container_class, function_name, readback_target or fn)
        else:
            # A local double starts no container and costs nothing; it is still
            # counted against the step's invocation budget.
            if self.policy is not None:
                self._check_budget(container_class, function_name)

        semaphore = self._semaphore(container_class)
        acquired = semaphore.acquire(timeout=self._acquire_timeout())
        if not acquired:
            self._refuse(
                container_class,
                function_name,
                "concurrency_gate_timeout",
                f"more than {self._concurrency_cap(container_class)} concurrent dispatches of {container_class}",
            )
        try:
            result = fn.remote(*args, **kwargs)
        except DispatchRefusal:
            raise
        except Exception as exc:  # the provider's own failure - not a refusal
            self.records.append(
                DispatchRecord(
                    step_id=self.policy.step_id if self.policy else "<no-policy>",
                    container_class=container_class,
                    function_name=function_name,
                    outcome="failed",
                    reason=type(exc).__name__,
                    detail=str(exc),
                    provider_callable=provider_callable,
                    at=time.time(),
                )
            )
            raise
        finally:
            semaphore.release()

        self.records.append(
            DispatchRecord(
                step_id=self.policy.step_id if self.policy else "<no-policy>",
                container_class=container_class,
                function_name=function_name,
                outcome="dispatched",
                provider_callable=provider_callable,
                at=time.time(),
            )
        )
        return result

    # -- the individual gates ------------------------------------------------------

    def _check_policy(self, container_class: str, function_name: str) -> None:
        if self.policy is None:
            self._refuse(
                container_class,
                function_name,
                "no_approved_step_policy",
                "a provider dispatch requires an approved step policy",
            )
        self.policy.validate()

    def _check_bounds(self, container_class: str, function_name: str) -> None:
        profile = self._profile(container_class)
        missing = profile.missing_bounds()
        if missing:
            self._refuse(
                container_class,
                function_name,
                "bounds_not_approved",
                f"{container_class}: " + ", ".join(missing),
            )

    def _check_egress(self, function_name: str) -> None:
        policy = self._egress(function_name)
        if policy is None:
            self._refuse(
                FUNCTION_CLASS.get(function_name, "unknown"),
                function_name,
                "no_egress_declaration",
                "the function has no per-container egress declaration (D29)",
            )
        if is_unset(policy.payload_cap_bytes) or is_unset(policy.protocol_allowance_bytes):
            self._refuse(
                policy.container_class,
                function_name,
                "egress_bound_not_approved",
                "the payload cap or the protocol allowance is required-but-unset (D29)",
            )

    def _check_ceiling(self, container_class: str, function_name: str) -> None:
        assert self.policy is not None
        deployed = self._profile(container_class).max_containers
        cap = int(self.policy.concurrency_caps.get(container_class, 0))
        if cap > deployed:
            self._refuse(
                container_class,
                function_name,
                "deployed_ceiling_too_low",
                f"cap(c)={cap} > max_containers_deployed(c)={deployed}",
            )

    def _check_budget(self, container_class: str, function_name: str) -> None:
        assert self.policy is not None
        budget = int(self.policy.invocation_budgets.get(container_class, 0))
        used = self.used.get(container_class, 0)
        if used >= budget:
            self._refuse(
                container_class,
                function_name,
                "invocation_budget_exhausted",
                f"{used} of {budget} dispatches of {container_class} used",
            )
        with self._lock:
            self.used[container_class] = used + 1

    def _check_payload_cap(self, function_name: str, args: Any) -> None:
        if function_name not in VOLUME_WRITING_FUNCTIONS or not args:
            return
        payload = args[0]
        try:
            payload_bytes = len(json.dumps(payload, default=str).encode("utf-8"))
        except (TypeError, ValueError):
            payload_bytes = len(repr(payload).encode("utf-8"))
        try:
            assert_payload_within_cap(payload_bytes, function_name)
        except Exception as exc:
            self._refuse(
                FUNCTION_CLASS.get(function_name, "unknown"),
                function_name,
                "payload_byte_cap",
                str(exc),
            )

    def _check_readback(self, container_class: str, function_name: str, target: Any) -> None:
        if self._readback_done.get(container_class):
            return
        try:
            effective = read_back_autoscaler(target)
        except DispatchRefusal as exc:
            self._refuse(container_class, function_name, exc.reason, exc.detail)
            return
        profile = self._profile(container_class)
        declared = {
            "min_containers": profile.min_containers,
            "max_containers": profile.max_containers,
            "buffer_containers": profile.buffer_containers,
            "scaledown_window": None
            if is_unset(profile.scaledown_window_sec)
            else int(profile.scaledown_window_sec),
        }
        for key, declared_value in declared.items():
            if declared_value is None:
                continue
            effective_value = effective.get(key)
            if effective_value is not None and int(effective_value) != int(declared_value):
                self._refuse(
                    container_class,
                    function_name,
                    "autoscaler_readback_mismatch",
                    f"{key}: deployed {effective_value} != declared {declared_value}",
                )
        self._readback_done[container_class] = True

    # -- misc ----------------------------------------------------------------------

    def _concurrency_cap(self, container_class: str) -> int:
        if self.policy is None:
            return 1
        return max(1, int(self.policy.concurrency_caps.get(container_class, 1)))

    def _acquire_timeout(self) -> float:
        if self.policy is None or is_unset(self.policy.wall_clock_budget_sec):
            return 0.0
        return max(1.0, float(self.policy.wall_clock_budget_sec))  # type: ignore[arg-type]

    def refused(self) -> List[DispatchRecord]:
        return [record for record in self.records if record.outcome == "refused"]

    def dispatched(self) -> List[DispatchRecord]:
        return [record for record in self.records if record.outcome == "dispatched"]


_ACTIVE_GATE: ContextVar[Optional[DispatchGate]] = ContextVar("r1_active_gate", default=None)


def current_gate() -> DispatchGate:
    """The gate of the running step, or an unauthorised gate when none is installed."""
    gate = _ACTIVE_GATE.get()
    if gate is None:
        return DispatchGate(policy=None)
    return gate


@contextmanager
def authorised_step(
    policy: StepPolicy,
    profiles: Optional[Dict[str, Any]] = None,
    egress_policies: Optional[Dict[str, Any]] = None,
) -> Iterator[DispatchGate]:
    """Install the approved policy of one step as the active dispatch contract."""
    gate = DispatchGate(policy=policy, profiles=profiles, egress_policies=egress_policies)
    token = _ACTIVE_GATE.set(gate)
    try:
        yield gate
    finally:
        _ACTIVE_GATE.reset(token)


def dispatch(container_class: str, function_name: str, fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Dispatch through the active gate - the only path out of this workflow."""
    return current_gate().dispatch(container_class, function_name, fn, *args, **kwargs)


__all__ = [
    "DispatchGate",
    "DispatchRecord",
    "DispatchRefusal",
    "StepPolicy",
    "VOLUME_WRITING_FUNCTIONS",
    "authorised_step",
    "current_gate",
    "dispatch",
    "read_back_autoscaler",
]
