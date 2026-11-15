"""The cumulative cost, egress and storage estimator of the regeneration steps.

The formulas are the ones of the architecture plan (§8.2.5) with the corrections the
reviews forced:

* **the cumulative cold containers of a class are bounded by the invocation count**,
  never by ``min(invocations, max_containers)``: ``max_containers`` is a *concurrency*
  cap, and a container that scales down and is replaced is a second container, so a
  concurrency cap may never clamp a cumulative quantity (D27, D29);
* the **storage interval is a sum**: the execution, the bounded post-execution
  interval before the publication, and the retention - not the two-term sum of the
  earlier draft (D28);
* the **storage is priced once, on the cycle's footprint** (D28, the maintainer's
  rule of the free tier): the provider's published allowance of **1 TiB/month** of
  volume storage is an account-level monthly allowance, so it is applied **once**
  to the cycle's time-weighted footprint - never per stage. Inside the allowance
  the storage of a run costs **USD 0**; the footprint itself is still computed
  (peak and time-weighted) and an excess is flagged.

**One accounting model, one command.** The numbers of the cost proposal are
produced by exactly one command::

    python -m benchmarks.r1_estimator --scenario benchmarks/evidence/r1_cost_scenario.json --provisional

The model has three parts and no fourth:

1. the **direct terms** of a stage - CPU, memory, GPU and egress - are additive over
   the cycle (they do not overlap in time);
2. the **storage** is priced once on the cycle's footprint and is then *allocated*
   back to the stages in proportion to their footprint x duration share, so the sum
   of the per-stage totals is exactly the cycle total - the standing baseline is
   never priced twice;
3. the **worst case** of a stage is the sum of its direct terms and its storage
   share; the cycle total is the sum of the stage totals, and the headroom is the
   difference to the cycle cap.

The estimator is fail-closed: if a bound or a rate is missing, the estimate is
*unavailable* with its reasons, and an unavailable estimate means the step is not
dispatchable. No rate is hardcoded in the repository - the rate card is an approval
input with its source and its reading date. Every result is
``PROVISIONAL_ONLY / NOT_DISPATCHABLE`` until the maintainer approves it, and a
cycle that does not fit the cap is reported as exactly ``BUDGET_INFEASIBLE``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.r1_bounds import (
    Bound,
    GPU_CLASS,
    PERSISTENCE,
    SANDBOX_CPU,
    STORAGE_FREE_ALLOWANCE_GIB_PER_MONTH,
    STORAGE_FREE_ALLOWANCE_SOURCE,
    Unset,
    egress_policy,
    ingress_policy,
    is_unset,
    profile_for,
)

#: The shortest calendar month - the conservative calendar treatment of the plan.
DAYS_PER_MONTH_BOUND = 28.0
SECONDS_PER_DAY = 86400.0
#: The retention interval: 30 days from the publication to the verified deletion.
DEFAULT_RETENTION_SEC = 30 * SECONDS_PER_DAY

GIB = 1024.0 ** 3

#: The status of every estimate of this repository until the maintainer approves
#: the bounds, the rate card and the stages.
PROVISIONAL_STATUS = "PROVISIONAL_ONLY / NOT_DISPATCHABLE"

#: The verdict of a cycle that fits the cap, and of one that does not.
VERDICT_WITHIN_BUDGET = "WITHIN_BUDGET"
VERDICT_INFEASIBLE = "BUDGET_INFEASIBLE"
VERDICT_UNAVAILABLE = "UNAVAILABLE"


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
    #: The provider's published free allowance of volume storage, in GiB/month.
    storage_free_allowance_gib_per_month: float = STORAGE_FREE_ALLOWANCE_GIB_PER_MONTH
    #: The rate of **inbound** traffic. The provider bills outbound traffic as
    #: egress; a download into the container is ingress and is not billed at the
    #: egress rate, so the ingress rate is 0.
    ingress_per_gib: float = 0.0
    #: The source of the ingress rate, with its reading date.
    ingress_source: str = ""

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
        allowance = data.get("storage_free_allowance_gib_per_month")
        ingress = data.get("ingress_per_gib")
        return cls(
            cpu_per_core_sec=float(data["cpu_per_core_sec"]),
            memory_per_gib_sec=float(data["memory_per_gib_sec"]),
            gpu_per_sec=float(data["gpu_per_sec"]),
            volume_per_gib_month=float(data["volume_per_gib_month"]),
            egress_per_gib=float(data["egress_per_gib"]),
            source=str(data.get("source", "<no source>")),
            read_at=str(data.get("read_at", "<no date>")),
            approved_by=data.get("approved_by"),
            storage_free_allowance_gib_per_month=(
                STORAGE_FREE_ALLOWANCE_GIB_PER_MONTH
                if allowance is None
                else float(allowance)
            ),
            ingress_per_gib=0.0 if ingress is None else float(ingress),
            ingress_source=str(data.get("ingress_source", "")),
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
    #: The functions whose provider call carries an **inbound** byte cap, per
    #: container class. The inbound bytes (the model download of R2p) are not
    #: billed at the egress rate: they are ingress.
    ingress_functions: Dict[str, List[str]] = field(default_factory=dict)
    #: The monetary ceiling proposed for this stage - the number the stage's worst
    #: case is reconciled against. It is a candidate, never an approval.
    ceiling_usd: Optional[float] = None
    #: How the volume baseline of this step was established. "UNKNOWN" means the
    #: baseline of the remote Volume is **not** measured by this evidence.
    baseline_status: str = "UNKNOWN"
    baseline_reason: str = ""
    #: How the volume increment of this step was established.
    incremental_status: str = "CANDIDATE_ESTIMATE"
    incremental_reason: str = ""


@dataclass
class StepEstimate:
    """The estimate of one step."""

    step_id: str
    available: bool
    total_usd: Optional[float]
    terms_usd: Dict[str, float] = field(default_factory=dict)
    quantities: Dict[str, Any] = field(default_factory=dict)
    unavailable_reasons: List[str] = field(default_factory=list)
    ceiling_usd: Optional[float] = None

    def to_record(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "available": self.available,
            "total_usd": self.total_usd,
            "terms_usd": self.terms_usd,
            "quantities": self.quantities,
            "unavailable_reasons": self.unavailable_reasons,
            "ceiling_usd": self.ceiling_usd,
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
    ingress_policies: Optional[Dict[str, Any]] = None,
) -> StepEstimate:
    """Estimate the **direct** terms of one step, or explain why it is unavailable.

    The direct terms are the CPU, the memory, the GPU, the egress and the
    ingress. The storage is **not** priced here: it is priced once on the
    cycle's footprint by :func:`aggregate_cycle` and allocated back to the
    stages, so the standing baseline is never priced twice.
    """
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

        # D29: the **inbound** bytes of the step are bounded separately and are
        # never charged at the outbound egress rate. The model download of R2p is
        # ingress: the provider bills outbound traffic as egress
        # (https://modal.com/docs/guide/network-egress-billing, read 2026-11-12).
        # An ingress declaration belongs to one dispatched function, so it has to
        # be declared for the step: a dispatched function with an ingress
        # declaration that the step does not declare makes the step unavailable.
        ingress_bytes = 0
        ingress_complete = True
        ingress_cap = 0
        ingress_all = _ingress_policies_for_class(container_class, ingress_policies)
        dispatched = set(step.egress_functions.get(container_class, []))
        declared_ingress = set(step.ingress_functions.get(container_class, []))
        for name in sorted(dispatched & set(ingress_all) - declared_ingress):
            reasons.append(
                f"{container_class}: the ingress bound of {name} is not declared for "
                "this step (D29)"
            )
            ingress_complete = False
        ingress_declarations = {
            name: policy
            for name, policy in ingress_all.items()
            if name in declared_ingress
        }
        for function_name, policy in ingress_declarations.items():
            if is_unset(policy.ingress_cap_bytes):
                ingress_complete = False
                reasons.append(
                    f"{container_class}: the ingress bound of {function_name} is "
                    "required-but-unset (D29)"
                )
                break
            ingress_cap = max(ingress_cap, int(policy.ingress_cap_bytes))
        if ingress_declarations:
            ingress_bytes = containers * ingress_cap
        quantities[container_class]["ingress_bytes"] = ingress_bytes
        quantities[container_class]["ingress_complete"] = ingress_complete
        quantities[container_class]["ingress_cap_bytes"] = ingress_cap
        quantities[container_class]["ingress_is_billed_as_egress"] = False
        if rate_card is not None and ingress_complete and ingress_declarations:
            terms[f"ingress_{container_class}"] = (
                ingress_bytes / GIB
            ) * rate_card.ingress_per_gib

    # D28: the volume footprint of the stage. The footprint is always reported -
    # the cost of it depends on the cycle's allowance.
    if is_unset(step.baseline_gib):
        reasons.append("the volume baseline is not measured")
    if is_unset(step.incremental_gib):
        reasons.append("the volume increment is not bounded")
    if is_unset(step.t_exec_sec):
        reasons.append("the wall-clock budget of the step is not declared")
    if is_unset(step.t_post_exec_to_publication_sec):
        reasons.append("the post-execution deadline before the publication is not declared")

    if not reasons and rate_card is not None:
        t_store = float(step.t_exec_sec) + float(step.t_post_exec_to_publication_sec)  # type: ignore[arg-type]
        volume_gib = float(step.baseline_gib) + float(step.incremental_gib)  # type: ignore[arg-type]
        quantities["volume"] = {
            "baseline_gib": float(step.baseline_gib),  # type: ignore[arg-type]
            "baseline_status": step.baseline_status,
            "baseline_reason": step.baseline_reason,
            "incremental_gib": float(step.incremental_gib),  # type: ignore[arg-type]
            "incremental_status": step.incremental_status,
            "incremental_reason": step.incremental_reason,
            "volume_gib": volume_gib,
            "t_exec_sec": float(step.t_exec_sec),  # type: ignore[arg-type]
            "t_post_exec_to_publication_sec": float(step.t_post_exec_to_publication_sec),  # type: ignore[arg-type]
            "t_store_sec": t_store,
            "t_store_days": t_store / SECONDS_PER_DAY,
        }

    if reasons or rate_card is None:
        return StepEstimate(
            step_id=step.step_id,
            available=False,
            total_usd=None,
            terms_usd=terms,
            quantities=quantities,
            unavailable_reasons=reasons,
            ceiling_usd=step.ceiling_usd,
        )

    total = sum(terms.values())
    return StepEstimate(
        step_id=step.step_id,
        available=True,
        total_usd=total,
        terms_usd=terms,
        quantities=quantities,
        unavailable_reasons=[],
        ceiling_usd=step.ceiling_usd,
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


def _ingress_policies_for_class(
    container_class: str, ingress_policies: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    from core.r1_bounds import INGRESS_POLICIES

    policies = ingress_policies if ingress_policies is not None else INGRESS_POLICIES
    return {
        name: policy
        for name, policy in policies.items()
        if policy.container_class == container_class
    }


# --------------------------------------------------------------------------------------
# The storage footprint (D28) - one model, priced once
# --------------------------------------------------------------------------------------


def storage_timeline(
    estimates: Sequence[StepEstimate], t_retention_sec: float = DEFAULT_RETENTION_SEC
) -> List[Dict[str, Any]]:
    """The footprint of the volume over the cycle, segment by segment.

    The worst case is assumed: a stage's increment is present for the **whole** of
    the stage's window, and the standing baseline of the next stage is the
    footprint the previous stage left behind. The last segment is the retention
    interval, at the final footprint.
    """
    segments: List[Dict[str, Any]] = []
    for estimate in estimates:
        volume = estimate.quantities.get("volume")
        if not volume:
            continue
        duration = float(volume["t_exec_sec"]) + float(volume["t_post_exec_to_publication_sec"])
        segments.append(
            {
                "step_id": estimate.step_id,
                "kind": "stage",
                "duration_sec": duration,
                "footprint_gib": float(volume["volume_gib"]),
                "baseline_status": volume.get("baseline_status", "UNKNOWN"),
                "baseline_reason": volume.get("baseline_reason", ""),
                "incremental_status": volume.get("incremental_status", "CANDIDATE_ESTIMATE"),
                "incremental_reason": volume.get("incremental_reason", ""),
            }
        )
    if segments:
        # The retention interval belongs to the last stage: it is that stage's
        # storage that is retained, so its cost is allocated to it and not lost.
        segments.append(
            {
                "step_id": segments[-1]["step_id"],
                "kind": "retention",
                "duration_sec": float(t_retention_sec),
                "footprint_gib": segments[-1]["footprint_gib"],
                "baseline_status": segments[-1]["baseline_status"],
                "baseline_reason": segments[-1]["baseline_reason"],
                "incremental_status": segments[-1]["incremental_status"],
                "incremental_reason": segments[-1]["incremental_reason"],
            }
        )
    return segments


def storage_account(
    segments: Sequence[Dict[str, Any]],
    rate_card: Optional[RateCard],
    t_retention_sec: float = DEFAULT_RETENTION_SEC,
) -> Dict[str, Any]:
    """Price the storage of the cycle **once**, on its footprint.

    The provider's allowance is an account-level monthly allowance, so it is applied
    once to the cycle: inside the allowance the storage costs USD 0, and only the
    excess above the allowance is billed.
    """
    total_seconds = sum(float(segment["duration_sec"]) for segment in segments)
    weighted_gib_seconds = sum(
        float(segment["duration_sec"]) * float(segment["footprint_gib"])
        for segment in segments
    )
    months = _months(total_seconds) if total_seconds else 1
    # The month unit of the quantity: 28 days. The calendar month count above is
    # the conservative treatment of the *window*; the allowance has to be
    # expressed in the same unit as the quantity it offsets, otherwise a short
    # window would be credited with more free storage than it can hold.
    month_units = total_seconds / (DAYS_PER_MONTH_BOUND * SECONDS_PER_DAY)
    gib_months = weighted_gib_seconds / (DAYS_PER_MONTH_BOUND * SECONDS_PER_DAY)
    allowance_per_month = (
        rate_card.storage_free_allowance_gib_per_month if rate_card else STORAGE_FREE_ALLOWANCE_GIB_PER_MONTH
    )
    allowance_gib_months = allowance_per_month * month_units
    billable_gib_months = max(0.0, gib_months - allowance_gib_months)
    storage_usd = (
        billable_gib_months * rate_card.volume_per_gib_month if rate_card else 0.0
    )
    peak_gib = max((float(segment["footprint_gib"]) for segment in segments), default=0.0)
    time_weighted_gib = weighted_gib_seconds / total_seconds if total_seconds else 0.0

    # The **capacity proof** is a separate question from the cost of the storage.
    # The cost of the cycle is USD 0 while the footprint stays inside the
    # provider's allowance - but that arithmetic rests on the baseline of the
    # remote Volume, and R1 performed no Volume operation: the baseline is not
    # measured by this evidence. The proof that the cycle fits the account is
    # therefore UNAVAILABLE until a read-only baseline measurement or a
    # defensible conservative bound exists.
    baseline_statuses = sorted({str(segment.get("baseline_status", "UNKNOWN")) for segment in segments})
    capacity_reasons: List[str] = []
    for segment in segments:
        if str(segment.get("baseline_status", "UNKNOWN")) != "MEASURED":
            reason = str(segment.get("baseline_reason", "")).strip()
            if reason and reason not in capacity_reasons:
                capacity_reasons.append(reason)
    capacity_proof = "AVAILABLE" if segments and not capacity_reasons else "UNAVAILABLE"
    incremental_statuses = sorted(
        {str(segment.get("incremental_status", "CANDIDATE_ESTIMATE")) for segment in segments}
    )

    return {
        "segments": list(segments),
        "total_window_sec": total_seconds,
        "total_window_days": total_seconds / SECONDS_PER_DAY,
        "months": months,
        "month_units": month_units,
        "peak_footprint_gib": peak_gib,
        "time_weighted_footprint_gib": time_weighted_gib,
        "footprint_gib_months": gib_months,
        "free_allowance_gib_per_month": allowance_per_month,
        "free_allowance_gib_months": allowance_gib_months,
        "billable_gib_months": billable_gib_months,
        "storage_usd": storage_usd,
        "within_free_allowance": billable_gib_months == 0.0,
        "allowance_source": STORAGE_FREE_ALLOWANCE_SOURCE,
        "baseline_status": baseline_statuses[0] if baseline_statuses else "UNKNOWN",
        "baseline_statuses": baseline_statuses,
        "incremental_status": incremental_statuses[0] if incremental_statuses else "UNKNOWN",
        "incremental_statuses": incremental_statuses,
        "capacity_proof": capacity_proof,
        "capacity_proof_reasons": capacity_reasons,
    }


def aggregate_cycle(
    estimates: Sequence[StepEstimate],
    rate_card: Optional[RateCard],
    t_retention_sec: float = DEFAULT_RETENTION_SEC,
    cycle_cap_usd: float = 20.0,
) -> Dict[str, Any]:
    """The worst case of the whole cycle, in one accounting model.

    The direct terms of the stages are additive. The storage is priced **once** on
    the cycle's footprint and is then allocated back to the stages in proportion to
    their footprint x duration share, so that the sum of the per-stage totals is
    exactly the cycle total.
    """
    unavailable: List[str] = []
    direct_total = 0.0
    for estimate in estimates:
        if not estimate.available:
            unavailable.extend(
                f"{estimate.step_id}: {reason}" for reason in estimate.unavailable_reasons
            )
            continue
        direct_total += float(estimate.total_usd or 0.0)

    segments = storage_timeline(estimates, t_retention_sec=t_retention_sec)
    storage = storage_account(segments, rate_card, t_retention_sec=t_retention_sec)
    storage_usd = float(storage["storage_usd"])

    weighted_total = sum(
        float(segment["duration_sec"]) * float(segment["footprint_gib"])
        for segment in segments
    )
    allocation: Dict[str, float] = {}
    for segment in segments:
        share = 0.0
        if weighted_total:
            share = (
                float(segment["duration_sec"]) * float(segment["footprint_gib"]) / weighted_total
            )
        allocation[segment["step_id"]] = allocation.get(segment["step_id"], 0.0) + share

    steps: List[Dict[str, Any]] = []
    total = 0.0
    for estimate in estimates:
        record = estimate.to_record()
        share = allocation.get(estimate.step_id, 0.0)
        storage_share_usd = storage_usd * share
        record["terms_usd"] = dict(record["terms_usd"])
        record["terms_usd"]["volume_storage"] = storage_share_usd
        stage_total = float(estimate.total_usd or 0.0) + storage_share_usd
        record["total_usd"] = stage_total if estimate.available else None
        record["storage_share"] = share
        ceiling = estimate.ceiling_usd
        record["headroom_usd"] = (
            None if ceiling is None or not estimate.available else float(ceiling) - stage_total
        )
        record["within_ceiling"] = (
            None if ceiling is None or not estimate.available else stage_total <= float(ceiling)
        )
        steps.append(record)
        if estimate.available:
            total += stage_total

    headroom = cycle_cap_usd - total
    if unavailable:
        verdict = VERDICT_UNAVAILABLE
    elif total > cycle_cap_usd:
        verdict = VERDICT_INFEASIBLE
    else:
        verdict = VERDICT_WITHIN_BUDGET

    return {
        "status": PROVISIONAL_STATUS,
        "verdict": verdict,
        "direct_terms_usd": direct_total,
        "storage": storage,
        "cycle_storage_usd": storage_usd,
        "storage_capacity_proof": storage["capacity_proof"],
        "storage_capacity_proof_reasons": storage["capacity_proof_reasons"],
        "storage_baseline_status": storage["baseline_status"],
        "storage_incremental_status": storage["incremental_status"],
        "steps": steps,
        "total_usd": total,
        "cycle_cap_usd": cycle_cap_usd,
        "headroom_usd": headroom,
        "within_cap": total <= cycle_cap_usd,
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
    ingress_policies: Dict[str, Any] = {}
    storage_baseline = scenario.get("storage_baseline", {})

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
        for function_name, overrides in step_data.get("candidate_ingress", {}).items():
            policy = ingress_policy(function_name)
            if policy is None:
                continue
            ingress_policies[function_name] = dataclasses.replace(policy, **overrides)

        ceiling = step_data.get("proposed_ceiling_usd")
        step = StepInputs(
            step_id=step_data["step_id"],
            invocations={k: int(v) for k, v in step_data.get("invocations", {}).items()},
            concurrency_caps={k: int(v) for k, v in step_data.get("concurrency_caps", {}).items()},
            baseline_gib=step_data.get("baseline_gib", scenario.get("baseline_gib", 0.0)),
            incremental_gib=step_data.get("incremental_gib", 0.0),
            t_exec_sec=step_data.get("t_exec_sec"),
            t_post_exec_to_publication_sec=step_data.get("t_post_exec_to_publication_sec"),
            t_retention_sec=float(step_data.get("t_retention_sec", DEFAULT_RETENTION_SEC)),
            egress_functions={
                container_class: list(names)
                for container_class, names in step_data.get("egress_functions", {}).items()
            },
            ingress_functions={
                container_class: list(names)
                for container_class, names in step_data.get("ingress_functions", {}).items()
            },
            ceiling_usd=None if ceiling is None else float(ceiling),
            baseline_status=str(
                step_data.get("baseline_status", storage_baseline.get("status", "UNKNOWN"))
            ),
            baseline_reason=str(
                step_data.get(
                    "baseline_reason", storage_baseline.get("reason", "")
                )
            ),
            incremental_status=str(
                step_data.get("incremental_status", "CANDIDATE_ESTIMATE")
            ),
            incremental_reason=str(step_data.get("incremental_reason", "")),
        )
        estimates.append(
            estimate_step(
                step,
                rate_card,
                step_profiles or profiles,
                egress_policies,
                allow_unapproved_rate_card=allow_unapproved_rate_card,
                ingress_policies=ingress_policies or None,
            )
        )

    aggregate = aggregate_cycle(
        estimates,
        rate_card,
        t_retention_sec=float(scenario.get("t_retention_sec", DEFAULT_RETENTION_SEC)),
        cycle_cap_usd=float(scenario.get("cycle_cap_usd", 20.0)),
    )
    return {
        "status": PROVISIONAL_STATUS,
        "verdict": aggregate["verdict"],
        "steps": aggregate["steps"],
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

    print(f"status: {result['status']}")
    for step in result["steps"]:
        if not step["available"]:
            print(f"{step['step_id']:<6} UNAVAILABLE")
            for reason in step["unavailable_reasons"]:
                print(f"    ! {reason}")
            continue
        total = float(step["total_usd"])
        ceiling = step.get("ceiling_usd")
        if ceiling is None:
            print(f"{step['step_id']:<6} worst_case=${total:.4f}")
        else:
            headroom = step.get("headroom_usd")
            within = step.get("within_ceiling")
            print(
                f"{step['step_id']:<6} worst_case=${total:.4f} ceiling=${float(ceiling):.2f} "
                f"headroom=${float(headroom):.4f} within_ceiling={within}"
            )
        for name, value in sorted(step["terms_usd"].items()):
            print(f"    {name:<28} ${value:.6f}")
    aggregate = result["aggregate"]
    storage = aggregate["storage"]
    print(
        f"storage: peak={storage['peak_footprint_gib']:.3f} GiB "
        f"time_weighted={storage['time_weighted_footprint_gib']:.3f} GiB "
        f"footprint={storage['footprint_gib_months']:.2f} GiB-month "
        f"allowance={storage['free_allowance_gib_months']:.2f} GiB-month "
        f"billable={storage['billable_gib_months']:.2f} GiB-month "
        f"cost=${storage['storage_usd']:.6f}"
    )
    print(
        f"storage status: baseline={storage['baseline_status']} "
        f"increment={storage['incremental_status']} "
        f"capacity_proof={storage['capacity_proof']}"
    )
    for reason in storage["capacity_proof_reasons"]:
        print(f"    ! {reason}")
    print(
        f"cycle  worst_case=${aggregate['total_usd']:.4f} cap=${aggregate['cycle_cap_usd']:.2f} "
        f"headroom=${aggregate['headroom_usd']:.4f} within_cap={aggregate['within_cap']}"
    )
    print(f"verdict: {aggregate['verdict']} ({result['status']})")
    for reason in aggregate["unavailable_reasons"]:
        print(f"    ! {reason}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "DEFAULT_RETENTION_SEC",
    "PROVISIONAL_STATUS",
    "RateCard",
    "StepEstimate",
    "StepInputs",
    "VERDICT_INFEASIBLE",
    "VERDICT_UNAVAILABLE",
    "VERDICT_WITHIN_BUDGET",
    "aggregate_cycle",
    "apply_candidate_bounds",
    "estimate_step",
    "main",
    "run_scenario",
    "storage_account",
    "storage_timeline",
]
