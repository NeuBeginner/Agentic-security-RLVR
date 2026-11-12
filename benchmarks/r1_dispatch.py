"""The single dispatch path of the evidence-regeneration workflow (plan D27).

The dispatch helper is the only path through which this workflow dispatches a Modal
call. It enforces, per step:

1. the **authorisation of the call site** - only the functions of the authorised
   trace may be dispatched at all; every other provider call site of the
   repository (the T4 dev agent, the Slither worker, the fault injection worker,
   the diagnostics, the GRPO training, the volume audit) is refused with the
   reason of the refusal registry of ``core/r1_bounds.py``;
2. an **invocation budget** per container class - at most ``invocations(c)``
   dispatches of class ``c``; the next one is refused and the refusal is recorded;
3. a **concurrency gate** per container class - at most ``cap(c)`` dispatches of
   class ``c`` in flight at the same time;
4. a **ceiling assertion** - ``cap(c) <= max_containers_deployed(c)``; if the step's
   approved cap exceeds the deployed ceiling the step is refused as
   "deployed ceiling too low";
5. the **completeness of the declared bounds** - while a required bound of the class is
   required-but-unset, no dispatch of that class happens (fail closed);
6. the **producer-enforced payload cap** of the volume-writing functions (D28);
7. the **egress declaration** of the dispatched function (D29);
8. the **autoscaler read-back** before the first container of the step - a
   **read-only** read of the four effective settings (``min_containers``,
   ``max_containers``, ``buffer_containers``, ``scaledown_window``). The mutating
   ``update_autoscaler()`` is never used as a read: in Modal SDK 1.5.5 it is an
   UPDATE RPC (``FunctionUpdateSchedulingParams``), so using it to verify the
   autoscaler would change the deployment while verifying it. A missing, None,
   malformed or mismatching field is a refusal, never a partial read.

A dispatch of a *real provider callable* additionally requires an approved step
policy. A local double (a test double) is passed through, because it starts no
container and costs nothing.

**The provider call itself.** The gate holds the provider object, not the guard that
would route the call back into the gate: a guard is unwrapped before the gates run
(``core.r1_bounds.unwrap_guard``), so a guarded call is dispatched exactly once. An
installed call site - one whose provider object carries the guard on its own
``remote`` - is called through the entry point that was captured before the guard was
installed; every other object is called through its own ``remote``.

**The invocation allowance is consumed only by a dispatch that actually starts a
provider call.** Every refusal - the authorisation, the policy, the bounds, the
egress, the ceiling, the payload cap, the concurrency gate, the read-back and the
budget itself - consumes nothing: a refused attempt starts no container, so it may
not cost an invocation. The check and the increment happen under **one** lock, so
two concurrent dispatches can never both pass the same remaining allowance.
"""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional

from core.r1_bounds import (
    AUTOSCALER_FIELDS,
    Bound,
    FUNCTION_CLASS,
    UnauthorisedCallSite,
    assert_authorised_call_site,
    assert_payload_within_cap,
    declared_autoscaler_settings,
    egress_policy,
    is_provider_callable,
    is_unset,
    is_installed_call_site,
    original_entrypoint,
    profile_for,
    unwrap_guard,
)

#: The functions that write to the persistent volume and are therefore capped (D28).
VOLUME_WRITING_FUNCTIONS = frozenset({"record_trajectory_remote"})

#: The reason codes of the refusals. They are stable: the evidence of the run
#: refers to them.
REFUSAL_REASONS = (
    "unauthorised_call_site",
    "no_approved_step_policy",
    "policy_incomplete",
    "estimate_above_ceiling",
    "bounds_not_approved",
    "no_egress_declaration",
    "egress_bound_not_approved",
    "deployed_ceiling_too_low",
    "payload_byte_cap",
    "concurrency_gate_timeout",
    "invocation_budget_exhausted",
    "autoscaler_readback_unavailable",
    "autoscaler_readback_missing_field",
    "autoscaler_readback_malformed",
    "autoscaler_readback_mismatch",
)


class DispatchRefusal(RuntimeError):
    """A refused dispatch, with the machine-readable reason that caused it."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        message = f"dispatch refused: {reason}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


class AutoscalerReadbackUnavailable(RuntimeError):
    """The effective autoscaler settings could not be read without mutating them."""


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


# --------------------------------------------------------------------------------------
# The autoscaler read-back (D27)
# --------------------------------------------------------------------------------------


def _run_coroutine_blocking(coro: Any) -> Any:
    """Run a coroutine from synchronous code, even inside a running loop."""
    try:
        from modal._utils.async_utils import run_coro_blocking
    except Exception:  # pragma: no cover - the SDK always ships it in 1.5.5
        run_coro_blocking = None
    if run_coro_blocking is not None:
        return run_coro_blocking(coro)
    import asyncio

    return asyncio.run(coro)


def _object_tag(function_name: str) -> str:
    """The provider object tag of a call site.

    A module-level function is tagged with its own name; a class method is a
    method of the class's service function, which carries the class's tag.
    """
    return function_name.split(".", 1)[0]


def provider_autoscaler_reader(target: Any, function_name: str = "") -> Dict[str, Any]:
    """Read the effective autoscaler settings with the provider's **read-only** RPC.

    Modal SDK 1.5.5 exposes no non-mutating autoscaler read: the only public
    accessor, ``Function.update_autoscaler()``, is an UPDATE RPC
    (``FunctionUpdateSchedulingParams``, ``modal/_functions.py:1204-1221``). Using
    it as a read would change the deployment while verifying it, so it is not used.

    This reader therefore uses the provider's read-only ``FunctionGet`` RPC - the
    same one the SDK itself uses to load a function
    (``modal/_functions.py:1315-1322``) - and reads
    ``FunctionData.autoscaler_settings`` from its response. The SDK drops that field
    when it builds its own ``FunctionInfo``, which is why the read happens here.

    Every failure - no credentials, no deployed object, an unexpected SDK shape -
    is an *unavailable* read and never a partial one: the step is refused. This
    reader has never been executed against the provider in this repository: no live
    provider call is part of the R1 evidence.

    The read is additionally **opt-in**: it needs ``R1_ENABLE_PROVIDER_READBACK=1``
    in the environment. Without it the read is unavailable and the step is refused,
    so that no test and no accidental code path can reach the provider.
    """
    if os.environ.get("R1_ENABLE_PROVIDER_READBACK", "").strip().lower() not in (
        "1",
        "true",
        "yes",
    ):
        raise AutoscalerReadbackUnavailable(
            "the provider read-back is disabled: R1_ENABLE_PROVIDER_READBACK is not "
            "set, so the effective autoscaler settings cannot be read"
        )
    try:
        from modal.client import Client
        from modal_proto import api_pb2
    except Exception as exc:  # pragma: no cover - the SDK always ships both
        raise AutoscalerReadbackUnavailable(
            f"the Modal client is not importable: {exc}"
        ) from exc

    app = getattr(target, "_app", None)
    app_name = getattr(app, "name", None)
    if not app_name:
        from core.config import config

        app_name = config.APP_NAME
    tag = _object_tag(function_name) if function_name else getattr(target, "_tag", None)
    if not tag:
        raise AutoscalerReadbackUnavailable(
            "the provider object tag of the dispatched function is unknown"
        )

    request = api_pb2.FunctionGetRequest(
        app_name=str(app_name),
        object_tag=str(tag),
        environment_name="main",
        app_version=0,
    )

    async def _read() -> Any:
        client = await Client.from_env()
        return await client.stub.FunctionGet(request)

    try:
        response = _run_coroutine_blocking(_read())
    except Exception as exc:
        raise AutoscalerReadbackUnavailable(
            f"the read-only FunctionGet of '{tag}' failed: {type(exc).__name__}: {exc}"
        ) from exc

    settings = getattr(getattr(response, "function", None), "autoscaler_settings", None)
    if settings is None:
        raise AutoscalerReadbackUnavailable(
            f"the provider response of '{tag}' carries no autoscaler settings"
        )
    return {name: getattr(settings, name, None) for name in AUTOSCALER_FIELDS}


def read_back_autoscaler(
    target: Any,
    function_name: str = "",
    reader: Optional[Callable[[Any, str], Dict[str, Any]]] = None,
) -> Dict[str, int]:
    """Read the effective autoscaler settings and validate all four fields.

    The read is read-only; the mutating ``update_autoscaler()`` is never used for
    it. The result is **complete or refused**: a missing field, a ``None`` field, a
    malformed value and a mismatch are four different refusals, and none of them
    lets a partial read pass.
    """
    reader = reader or provider_autoscaler_reader
    try:
        settings = reader(target, function_name)
    except AutoscalerReadbackUnavailable as exc:
        raise DispatchRefusal("autoscaler_readback_unavailable", str(exc))
    except DispatchRefusal:
        raise
    except Exception as exc:
        raise DispatchRefusal(
            "autoscaler_readback_unavailable", f"{type(exc).__name__}: {exc}"
        )

    if not isinstance(settings, dict):
        raise DispatchRefusal(
            "autoscaler_readback_malformed",
            f"the read-back returned {type(settings).__name__}, not a mapping",
        )

    validated: Dict[str, int] = {}
    for field_name in AUTOSCALER_FIELDS:
        if field_name not in settings:
            raise DispatchRefusal(
                "autoscaler_readback_missing_field",
                f"{field_name} is missing from the read-back",
            )
        value = settings[field_name]
        if value is None:
            raise DispatchRefusal(
                "autoscaler_readback_missing_field",
                f"{field_name} is None in the read-back",
            )
        if isinstance(value, bool) or not isinstance(value, int):
            raise DispatchRefusal(
                "autoscaler_readback_malformed",
                f"{field_name} is {value!r}, not an integer",
            )
        if value < 0 or (field_name == "scaledown_window" and value <= 0):
            raise DispatchRefusal(
                "autoscaler_readback_malformed",
                f"{field_name} is {value!r}, which is not a valid setting",
            )
        validated[field_name] = int(value)
    return validated


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
        autoscaler_reader: Optional[Callable[[Any, str], Dict[str, Any]]] = None,
    ) -> None:
        self.policy = policy
        self.profiles = profiles or {}
        self.egress_policies = egress_policies or {}
        self.autoscaler_reader = autoscaler_reader
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
        # A guard is unwrapped **before** the gates run: the gate holds the
        # provider object itself, so a guarded call is dispatched exactly once.
        # A second pass through the gate would take the concurrency semaphore a
        # second time and stall the dispatch instead of performing it.
        fn = unwrap_guard(fn)
        provider_callable = is_provider_callable(fn)

        if provider_callable:
            self._check_authorisation(container_class, function_name)
            self._check_policy(container_class, function_name)
            self._check_bounds(container_class, function_name)
            self._check_egress(function_name)
            self._check_ceiling(container_class, function_name)
            self._check_payload_cap(function_name, args)
            self._check_readback(container_class, function_name, readback_target or fn)

        # A guard (core.r1_bounds.GuardedRemote / GuardedClassMethod) routes the
        # call through this gate as well. The nested dispatch must not consume the
        # invocation allowance a second time: the outer dispatch already did.
        nested = _IN_DISPATCH.get() > 0
        token = _IN_DISPATCH.set(_IN_DISPATCH.get() + 1)
        try:
            semaphore = self._semaphore(container_class)
            # A nested dispatch runs while the outer dispatch holds the permit of
            # the class, so it must not take it a second time: it would wait for
            # a permit that only the outer dispatch can release.
            acquired = True
            if not nested:
                acquired = semaphore.acquire(timeout=self._acquire_timeout())
            if not acquired:
                self._refuse(
                    container_class,
                    function_name,
                    "concurrency_gate_timeout",
                    f"more than {self._concurrency_cap(container_class)} concurrent dispatches of {container_class}",
                )
            try:
                # The allowance is consumed here - after every gate, immediately
                # before the call - so a refused attempt costs no invocation.
                if not nested:
                    self._consume_budget(container_class, function_name)
                try:
                    # The provider call itself. An installed call site is called
                    # through the entry point that was captured before the guard
                    # was installed on the object's own 'remote': calling the
                    # guarded 'remote' here would route the call back into this
                    # gate. Everything else is called through its own 'remote'.
                    if is_installed_call_site(function_name, fn):
                        result = original_entrypoint(function_name)(*args, **kwargs)  # type: ignore[misc]
                    else:
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
                if not nested:
                    semaphore.release()
        finally:
            _IN_DISPATCH.reset(token)

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

    def _check_authorisation(self, container_class: str, function_name: str) -> None:
        """Only the call sites of the authorised trace may be dispatched."""
        try:
            assert_authorised_call_site(function_name)
        except UnauthorisedCallSite as exc:
            self._refuse(
                container_class,
                function_name,
                "unauthorised_call_site",
                exc.reason,
            )

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

    def _consume_budget(self, container_class: str, function_name: str) -> None:
        """Check and consume one invocation of the class's allowance - atomically.

        The check and the increment happen under **one** lock: two concurrent
        dispatches can therefore never both pass the same remaining allowance.
        """
        if self.policy is None:
            return
        budget = int(self.policy.invocation_budgets.get(container_class, 0))
        with self._lock:
            used = self.used.get(container_class, 0)
            if used >= budget:
                self._refuse(
                    container_class,
                    function_name,
                    "invocation_budget_exhausted",
                    f"{used} of {budget} dispatches of {container_class} used",
                )
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
        """Read the effective autoscaler settings back and compare all four fields."""
        if self._readback_done.get(container_class):
            return
        try:
            effective = read_back_autoscaler(
                target, function_name=function_name, reader=self.autoscaler_reader
            )
        except DispatchRefusal as exc:
            self._refuse(container_class, function_name, exc.reason, exc.detail)
            return
        profile = self._profile(container_class)
        declared = declared_autoscaler_settings(profile)
        for field_name in AUTOSCALER_FIELDS:
            declared_value = declared[field_name]
            if declared_value is None:
                self._refuse(
                    container_class,
                    function_name,
                    "autoscaler_readback_malformed",
                    f"{field_name}: the declaration is required-but-unset, so it "
                    "cannot be read back (D27)",
                )
            effective_value = effective[field_name]
            if int(effective_value) != int(declared_value):
                self._refuse(
                    container_class,
                    function_name,
                    "autoscaler_readback_mismatch",
                    f"{field_name}: deployed {effective_value} != declared {declared_value}",
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

    def used_allowance(self, container_class: str) -> int:
        """The invocation allowance that was consumed by real dispatches."""
        return int(self.used.get(container_class, 0))


_ACTIVE_GATE: ContextVar[Optional[DispatchGate]] = ContextVar("r1_active_gate", default=None)

#: The depth of the dispatch nesting. A guard routes a call through the same gate,
#: so a nested dispatch must not consume the invocation allowance twice.
_IN_DISPATCH: ContextVar[int] = ContextVar("r1_in_dispatch", default=0)


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
    autoscaler_reader: Optional[Callable[[Any, str], Dict[str, Any]]] = None,
) -> Iterator[DispatchGate]:
    """Install the approved policy of one step as the active dispatch contract."""
    gate = DispatchGate(
        policy=policy,
        profiles=profiles,
        egress_policies=egress_policies,
        autoscaler_reader=autoscaler_reader,
    )
    token = _ACTIVE_GATE.set(gate)
    try:
        yield gate
    finally:
        _ACTIVE_GATE.reset(token)


def dispatch_through_gate(
    container_class: str, function_name: str, fn: Any, *args: Any, **kwargs: Any
) -> Any:
    """The single dispatch path - the guards and the callers use the same gate.

    Every provider call of this repository ends up here: the module-level guard and
    the class-method guard of ``core/r1_bounds.py`` route through it, and the
    producer's adapters call it explicitly. There is no second path.
    """
    return current_gate().dispatch(container_class, function_name, fn, *args, **kwargs)


def dispatch(container_class: str, function_name: str, fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Dispatch through the active gate - the only path out of this workflow."""
    return dispatch_through_gate(container_class, function_name, fn, *args, **kwargs)


__all__ = [
    "AutoscalerReadbackUnavailable",
    "DispatchGate",
    "DispatchRecord",
    "DispatchRefusal",
    "REFUSAL_REASONS",
    "StepPolicy",
    "VOLUME_WRITING_FUNCTIONS",
    "authorised_step",
    "current_gate",
    "dispatch",
    "dispatch_through_gate",
    "provider_autoscaler_reader",
    "read_back_autoscaler",
]
