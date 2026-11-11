"""The cumulative cost, egress and storage estimator of the regeneration steps.

The formulas are the ones of the architecture plan (§8.2.5) with the corrections the
reviews forced:

* **the cumulative cold containers of a class are bounded by the invocation count**,
  never by ``min(invocations, max_containers)``: ``max_containers`` is a *concurrency*
  cap, and a container that scales down and is replaced is a second container, so a
  concurrency cap may never clamp a cumulative quantity (D27, D29);
* the **storage interval is a sum**: the execution, the bounded post-execution
  interval before the publication, and the retention - not the two-term sum of the
  earlier draft (D28).

The estimator is fail-closed: if a bound or a rate is missing, the estimate is
*unavailable* with its reasons, and an unavailable estimate means the step is not
dispatchable. No rate is hardcoded in the repository - the rate card is an approval
input with its source and its reading date.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from core.r1_bounds import (
    Bound,
    GPU_CLASS,
    PERSISTENCE,
    SANDBOX_CPU,
    Unset,
    egress_policy,
    is_unset,
    profile_for,
)
#: The shortest calendar month - the conservative calendar treatment of the plan.
DAYS_PER_MONTH_BOUND = 28.0
SECONDS_PER_DAY = 86400.0
#: The retention interval: 30 days from the publication to the verified deletion.
DEFAULT_RETENTION_SEC = 30 * SECONDS_PER_DAY

GIB = 1024.0 ** 3


@dataclass(frozen=True)
class RateCard:
    """The provider's published rates - an approval input, never a code constant."""

    cpu_per_core_sec: float
    memory_per_gib_sec: float
    gpu_per_sec: float
    volume_per_gib_month: float
    egress_per_gib: float
    source: str
    read_at: str
    approved_by: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RateCard":
        missing = [
            name
            for name in (
                "cpu_per_core_sec",
                "memory_per_gib_sec",
                "gpu_per_sec",
                "volume_per_gib_month",
                "egress_per_gib",
            )
            if data.get(name) is None
        ]
        if missing:
            raise ValueError(f"the rate card is missing: {', '.join(missing)}")
        return cls(
            cpu_per_core_sec=float(data["cpu_per_core_sec"]),
            memory_per_gib_sec=float(data["memory_per_gib_sec"]),
            gpu_per_sec=float(data["gpu_per_sec"]),
            volume_per_gib_month=float(data["volume_per_gib_month"]),
            egress_per_gib=float(data["egress_per_gib"]),
            source=str(data.get("source", "<no source>")),
            read_at=str(data.get("read_at", "<no date>")),
            approved_by=data.get("approved_by"),
        )

    @classmethod
    def from_file(cls, path: str) -> "RateCard":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    def is_approved(self) -> bool:
        return bool(self.approved_by)


@dataclass(frozen=True)
class StepInputs:
    """The declared quantities of one step."""

    step_id: str
    invocations: Dict[str, int]
    concurrency_caps: Dict[str, int]
    baseline_gib: Bound
    incremental_gib: Bound
    t_exec_sec: Bound
    t_post_exec_to_publication_sec: Bound
    t_retention_sec: float = DEFAULT_RETENTION_SEC
    #: The functions the step dispatches, per container class. The per-container
    #: egress cap is the largest cap among them: a container serves one invocation
    #: at a time, so the step's egress is bounded by invocations x the largest
    #: per-invocation cap.
    egress_functions: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class StepEstimate:
    """The estimate of one step."""

    step_id: str
    available: bool
    total_usd: Optional[float]
    terms_usd: Dict[str, float] = field(default_factory=dict)
    quantities: Dict[str, Any] = field(default_factory=dict)
    unavailable_reasons: List[str] = field(default_factory=list)

    def to_record(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "available": self.available,
            "total_usd": self.total_usd,
            "terms_usd": self.terms_usd,
            "quantities": self.quantities,
            "unavailable_reasons": self.unavailable_reasons,
        }


def _months(t_store_sec: float) -> int:
    """``1 + ceil(T_store / 28 days)`` - the conservative calendar treatment."""
    days = t_store_sec / SECONDS_PER_DAY
    return 1 + int(math.ceil(days / DAYS_PER_MONTH_BOUND))


def apply_candidate_bounds(profile: Any, overrides: Dict[str, Any]) -> Any:
    """Return a copy of ``profile`` with the candidate bounds applied.

    The candidates are **proposals** for the maintainer's approval - they are never
    the deployment's declared values.
    """
    fields = {f.name for f in dataclasses.fields(profile)}
    unknown = [key for key in overrides if key not in fields]
    if unknown:
        raise ValueError(f"unknown bound(s): {', '.join(unknown)}")
    return dataclasses.replace(profile, **overrides)


def estimate_step(
    step: StepInputs,
    rate_card: Optional[RateCard],
    profiles: Optional[Dict[str, Any]] = None,
    egress_policies: Optional[Dict[str, Any]] = None,
    allow_unapproved_rate_card: bool = False,
) -> StepEstimate:
    """Estimate one step, or explain why the estimate is unavailable."""
    reasons: List[str] = []
    terms: Dict[str, float] = {}
    quantities: Dict[str, Any] = {}

    if rate_card is None:
        reasons.append("no rate card: the provider's rates are an approval input")
    elif not rate_card.is_approved() and not allow_unapproved_rate_card:
        reasons.append(
            f"the rate card is not approved (read {rate_card.read_at} from {rate_card.source})"
        )
    if rate_card is not None:
        quantities["rate_card_approved"] = rate_card.is_approved()
        quantities["rate_card_source"] = rate_card.source
        quantities["rate_card_read_at"] = rate_card.read_at

    for container_class, invocations in step.invocations.items():
        profile = (profiles or {}).get(container_class) or profile_for(container_class)
        missing = profile.missing_bounds()
        if missing:
            reasons.append(f"{container_class}: bounds not approved: {', '.join(missing)}")
            continue

        # D27/D29: the cumulative cold containers are bounded by the invocation
        # count. max_containers is a concurrency cap and never clamps this.
        containers = int(invocations)
        concurrent = min(containers, int(step.concurrency_caps.get(container_class, containers)))
        deployed_ceiling = profile.max_containers
        if int(step.concurrency_caps.get(container_class, 0)) > deployed_ceiling:
            reasons.append(
                f"{container_class}: cap(c)={step.concurrency_caps.get(container_class)} exceeds the "
                f"deployed ceiling {deployed_ceiling}"
            )
            continue

        t_billable = profile.billable_lifetime_sec()

        cpu_core_seconds = profile.cpu_limit() * t_billable * containers
        memory_gib_seconds = profile.memory_limit_gib() * t_billable * containers
        gpu_seconds = t_billable * containers if profile.gpu_type else 0.0

        quantities[container_class] = {
            "invocations": containers,
            "cold_containers_bound": containers,
            "concurrent_containers": concurrent,
            "deployed_max_containers": deployed_ceiling,
            "t_billable_sec": t_billable,
            "cpu_core_seconds": cpu_core_seconds,
            "memory_gib_seconds": memory_gib_seconds,
            "gpu_seconds": gpu_seconds,
        }

        if rate_card is not None:
            terms[f"cpu_{container_class}"] = cpu_core_seconds * rate_card.cpu_per_core_sec
            terms[f"memory_{container_class}"] = memory_gib_seconds * rate_card.memory_per_gib_sec
            if profile.gpu_type:
                terms[f"gpu_{container_class}"] = gpu_seconds * rate_card.gpu_per_sec

        # D29: the egress of the step is the sum over the step's containers. A
        # container serves one invocation at a time, so the per-container cap is the
        # largest cap among the functions the step dispatches.
        egress_bytes = 0
        egress_complete = True
        policies = _policies_for_class(container_class, egress_policies)
        selected = step.egress_functions.get(container_class)
        if selected is not None:
            policies = {name: policy for name, policy in policies.items() if name in selected}
        payload_cap = 0
        protocol_allowance = 0
        for function_name, policy in policies.items():
            if is_unset(policy.payload_cap_bytes) or is_unset(policy.protocol_allowance_bytes):
                egress_complete = False
                reasons.append(
                    f"{container_class}: the egress bound of {function_name} is required-but-unset (D29)"
                )
                break
            payload_cap = max(payload_cap, int(policy.payload_cap_bytes))
            protocol_allowance = max(protocol_allowance, int(policy.protocol_allowance_bytes))
        egress_bytes = containers * (payload_cap + protocol_allowance)
        quantities[container_class]["egress_bytes"] = egress_bytes
        quantities[container_class]["egress_complete"] = egress_complete
        quantities[container_class]["egress_payload_cap_bytes"] = payload_cap
        quantities[container_class]["egress_protocol_allowance_bytes"] = protocol_allowance
        if rate_card is not None and egress_complete:
            terms[f"egress_{container_class}"] = (egress_bytes / GIB) * rate_card.egress_per_gib

    # D28: the volume quantity and the storage interval.
    if is_unset(step.baseline_gib):
        reasons.append("the volume baseline is not measured")
    if is_unset(step.incremental_gib):
        reasons.append("the volume increment is not bounded")
    if is_unset(step.t_exec_sec):
        reasons.append("the wall-clock budget of the step is not declared")
    if is_unset(step.t_post_exec_to_publication_sec):
        reasons.append("the post-execution deadline before the publication is not declared")

    if not reasons and rate_card is not None:
        t_store = float(step.t_exec_sec) + float(step.t_post_exec_to_publication_sec) + float(step.t_retention_sec)  # type: ignore[arg-type]
        months = _months(t_store)
        volume_gib = float(step.baseline_gib) + float(step.incremental_gib)  # type: ignore[arg-type]
        volume_gib_months = volume_gib * months
        quantities["volume"] = {
            "baseline_gib": volume_gib - float(step.incremental_gib),  # type: ignore[arg-type]
            "incremental_gib": float(step.incremental_gib),  # type: ignore[arg-type]
            "volume_gib": volume_gib,
            "t_exec_sec": float(step.t_exec_sec),  # type: ignore[arg-type]
            "t_post_exec_to_publication_sec": float(step.t_post_exec_to_publication_sec),  # type: ignore[arg-type]
            "t_retention_sec": float(step.t_retention_sec),
            "t_store_sec": t_store,
            "t_store_days": t_store / SECONDS_PER_DAY,
            "months": months,
            "volume_gib_months": volume_gib_months,
        }
        terms["volume_storage"] = volume_gib_months * rate_card.volume_per_gib_month

    if reasons or rate_card is None:
        return StepEstimate(
            step_id=step.step_id,
            available=False,
            total_usd=None,
            terms_usd=terms,
            quantities=quantities,
            unavailable_reasons=reasons,
        )

    total = sum(terms.values())
    return StepEstimate(
        step_id=step.step_id,
        available=True,
        total_usd=total,
        terms_usd=terms,
        quantities=quantities,
        unavailable_reasons=[],
    )


def _policies_for_class(
    container_class: str, egress_policies: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    from core.r1_bounds import EGRESS_POLICIES

    policies = egress_policies if egress_policies is not None else EGRESS_POLICIES
    return {
        name: policy
        for name, policy in policies.items()
        if policy.container_class == container_class
    }


def aggregate_cycle(
    estimates: Sequence[StepEstimate],
    rate_card: Optional[RateCard],
    baseline_gib: float = 0.0,
    total_incremental_gib: float = 0.0,
    total_t_exec_sec: float = 0.0,
    max_t_post_exec_sec: float = 0.0,
    t_retention_sec: float = DEFAULT_RETENTION_SEC,
    cycle_cap_usd: float = 20.0,
) -> Dict[str, Any]:
    """The worst-case aggregate of the whole cycle.

    The compute and the egress terms are summed per step - they do not overlap. The
    **storage** term is not: the volume's bytes exist from the first write until the
    deletion is verified, so the cycle prices them **once** over the cycle's window
    instead of pricing the same standing baseline in every step's window.
    """
    compute_and_egress = 0.0
    per_step_storage = 0.0
    unavailable: List[str] = []
    for estimate in estimates:
        if not estimate.available:
            unavailable.extend(f"{estimate.step_id}: {reason}" for reason in estimate.unavailable_reasons)
            continue
        for name, value in estimate.terms_usd.items():
            if name == "volume_storage":
                per_step_storage += value
            else:
                compute_and_egress += value

    t_store = total_t_exec_sec + max_t_post_exec_sec + t_retention_sec
    months = _months(t_store)
    volume_gib = baseline_gib + total_incremental_gib
    cycle_storage_usd = volume_gib * months * (rate_card.volume_per_gib_month if rate_card else 0.0)
    total = compute_and_egress + cycle_storage_usd
    return {
        "compute_and_egress_usd": compute_and_egress,
        "cycle_storage_usd": cycle_storage_usd,
        "naive_sum_of_per_step_storage_usd": per_step_storage,
        "total_usd": total,
        "cycle_cap_usd": cycle_cap_usd,
        "headroom_usd": cycle_cap_usd - total,
        "within_cap": total <= cycle_cap_usd,
        "storage_window": {
            "t_exec_sec": total_t_exec_sec,
            "t_post_exec_to_publication_sec": max_t_post_exec_sec,
            "t_retention_sec": t_retention_sec,
            "t_store_sec": t_store,
            "t_store_days": t_store / SECONDS_PER_DAY,
            "months": months,
            "volume_gib": volume_gib,
        },
        "unavailable_reasons": unavailable,
    }


# --------------------------------------------------------------------------------------
# CLI - the numbers of the cost proposal are produced by this command
# --------------------------------------------------------------------------------------


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run_scenario(
    scenario: Dict[str, Any],
    rate_card: Optional[RateCard],
    allow_unapproved_rate_card: bool = False,
) -> Dict[str, Any]:
    """Evaluate a scenario file: the per-step estimates and the cycle aggregate."""
    estimates: List[StepEstimate] = []
    profiles: Dict[str, Any] = {}
    egress_policies: Dict[str, Any] = {}
    baseline = float(scenario.get("baseline_gib", 0.0))
    total_incremental = 0.0
    total_t_exec = 0.0
    max_t_post = 0.0

    for step_data in scenario.get("steps", []):
        overrides_by_class = step_data.get("candidate_bounds", {})
        step_profiles: Dict[str, Any] = {}
        for container_class, overrides in overrides_by_class.items():
            profile = profile_for(container_class)
            step_profiles[container_class] = apply_candidate_bounds(profile, overrides)
        for container_class, profile in step_profiles.items():
            profiles[container_class] = profile
        for function_name, overrides in step_data.get("candidate_egress", {}).items():
            policy = egress_policy(function_name)
            if policy is None:
                continue
            egress_policies[function_name] = dataclasses.replace(policy, **overrides)

        step = StepInputs(
            step_id=step_data["step_id"],
            invocations={k: int(v) for k, v in step_data.get("invocations", {}).items()},
            concurrency_caps={k: int(v) for k, v in step_data.get("concurrency_caps", {}).items()},
            baseline_gib=step_data.get("baseline_gib", baseline),
            incremental_gib=step_data.get("incremental_gib", 0.0),
            t_exec_sec=step_data.get("t_exec_sec"),
            t_post_exec_to_publication_sec=step_data.get("t_post_exec_to_publication_sec"),
            t_retention_sec=float(step_data.get("t_retention_sec", DEFAULT_RETENTION_SEC)),
            egress_functions={
                container_class: list(names)
                for container_class, names in step_data.get("egress_functions", {}).items()
            },
        )
        estimates.append(
            estimate_step(
                step,
                rate_card,
                step_profiles or profiles,
                egress_policies,
                allow_unapproved_rate_card=allow_unapproved_rate_card,
            )
        )
        total_incremental += float(step_data.get("incremental_gib", 0.0) or 0.0)
        total_t_exec += float(step_data.get("t_exec_sec", 0.0) or 0.0)
        max_t_post = max(max_t_post, float(step_data.get("t_post_exec_to_publication_sec", 0.0) or 0.0))

    aggregate = aggregate_cycle(
        estimates,
        rate_card,
        baseline_gib=baseline,
        total_incremental_gib=total_incremental,
        total_t_exec_sec=total_t_exec,
        max_t_post_exec_sec=max_t_post,
        cycle_cap_usd=float(scenario.get("cycle_cap_usd", 20.0)),
    )
    return {
        "steps": [estimate.to_record() for estimate in estimates],
        "aggregate": aggregate,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, help="the scenario JSON file")
    parser.add_argument("--rate-card", default=None, help="the rate card JSON file")
    parser.add_argument("--json", action="store_true", help="print the raw JSON record")
    parser.add_argument(
        "--provisional",
        action="store_true",
        help="compute with an unapproved rate card (the cost proposal only; a dispatch still refuses)",
    )
    args = parser.parse_args(argv)

    scenario = _load_json(args.scenario)
    rate_card_path = args.rate_card or scenario.get("rate_card")
    rate_card = RateCard.from_file(rate_card_path) if rate_card_path else None
    result = run_scenario(scenario, rate_card, allow_unapproved_rate_card=args.provisional)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    for step in result["steps"]:
        state = "AVAILABLE" if step["available"] else "UNAVAILABLE"
        total = "n/a" if step["total_usd"] is None else f"${step['total_usd']:.4f}"
        print(f"{step['step_id']:<6} {state:<12} total={total}")
        for name, value in sorted(step["terms_usd"].items()):
            print(f"    {name:<28} ${value:.6f}")
        for reason in step["unavailable_reasons"]:
            print(f"    ! {reason}")
    aggregate = result["aggregate"]
    print(
        f"cycle  total=${aggregate['total_usd']:.4f} cap=${aggregate['cycle_cap_usd']:.2f} "
        f"headroom=${aggregate['headroom_usd']:.4f} within_cap={aggregate['within_cap']}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "DEFAULT_RETENTION_SEC",
    "RateCard",
    "StepEstimate",
    "StepInputs",
    "aggregate_cycle",
    "apply_candidate_bounds",
    "estimate_step",
    "main",
    "run_scenario",
]
