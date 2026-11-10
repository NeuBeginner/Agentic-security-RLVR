"""
benchmarks/evaluator.py

Independent Post-Execution Evaluator for Aegis-RLVR Benchmarks.
Consumes execution artifacts and private GroundTruth to calculate empirical confusion matrices.
Guarantees:
- Ground truth is strictly inaccessible during execution.
- Fail-Closed Semantics: If ANY target is UNAVAILABLE or FAILED or INCOMPLETE,
  metrics are NOT computed (all set to None), prohibiting synthetic/misleading 0% or 100% metrics.
- Incomplete/failed runs are NEVER treated as negative detections: their detection is
  None and their detection state is NOT_EVALUATED.
- Mathematical consistency across TP, FP, TN, FN, Precision, Recall, F1, FPR, and FNR.
- Cost metrics are only reported when real measured token usage/pricing is present.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from benchmarks.protocol import (
    TargetExecutionArtifact,
    GroundTruth,
    BaselineEvaluationResult,
    ExecutionStatus,
)


#: The verdicts of a **completed** execution that mean "the run produced no
#: valid finding". They are a negative result of a successful execution - a
#: compilation error, a runtime revert, a malformed answer, a rejected cheatcode
#: attempt and a safe control that behaved safely are all "nothing was found",
#: never "a breach".
NEGATIVE_EXECUTION_VERDICTS = (
    "COMPILATION_ERROR",
    "RUNTIME_REVERT",
    "GENERATION_FORMAT_ERROR",
    "SAFE_RUN",
    "CHEATCODE_DETECTED",
)

#: The verdicts that say the **audit itself** did not run: the harness, the
#: environment or the toolchain failed. Such a run produced no valid conclusion
#: about the target, so it is not a negative finding either - it is not
#: evaluated at all. The training path excludes the very same category from the
#: group statistics for the same reason (``core/schemas.py``,
#: ``ResultCategory.INFRA_ERROR``).
INVALID_EXECUTION_VERDICTS = (
    "INFRA_ERROR",
)

#: The state of the detection of one target in the report.
DETECTION_STATE_POSITIVE = "POSITIVE"
DETECTION_STATE_NEGATIVE = "NEGATIVE"
DETECTION_STATE_NOT_EVALUATED = "NOT_EVALUATED"


def resolve_detection(
    artifact: TargetExecutionArtifact,
) -> Tuple[Optional[bool], str]:
    """
    The detection of one target execution - **fail-closed**.

    A negative detection exists only for a **successfully completed, semantically
    valid** execution. An execution that failed or was unavailable produced no
    finding at all: its detection is ``None`` (``NOT_EVALUATED``), never
    ``False``. The same holds for a completed execution whose verdict says that
    the audit itself did not run (``INFRA_ERROR``).

    The verdict of a completed execution is preserved: a compilation error, a
    runtime revert, a format error, a rejected cheatcode attempt and a safe run
    stay negative findings of a run that did complete.

    A **missing** verdict is not a reason to discard the evaluation: the
    verdict is optional metadata - the LLM auditor adapters never set one
    (``benchmarks/adapters.py``) - and the completion of the execution is the
    statement that the audit ran. Only a verdict that names an **invalid**
    category discards the evaluation, and the only one is ``INFRA_ERROR``:
    the verdict that says the audit itself did not run.
    """
    if artifact.status != ExecutionStatus.SUCCESS:
        return None, DETECTION_STATE_NOT_EVALUATED

    if artifact.security_verdict in INVALID_EXECUTION_VERDICTS:
        return None, DETECTION_STATE_NOT_EVALUATED

    if artifact.security_verdict in NEGATIVE_EXECUTION_VERDICTS:
        return False, DETECTION_STATE_NEGATIVE

    detected = bool(artifact.detected)
    return detected, (DETECTION_STATE_POSITIVE if detected else DETECTION_STATE_NEGATIVE)


def _presented_breach_counters(
    artifact: TargetExecutionArtifact, detection_state: str
) -> Tuple[int, int]:
    """
    The breach counters as the report presents them.

    The counters of the producer are the presented counters **only** when the
    presented detection is a positive finding. A report never shows a breach
    count next to a target that found nothing: a run that produced no finding
    has no breaches either. The raw claim of the producer is preserved by the
    caller under ``producer_*``.
    """
    if detection_state != DETECTION_STATE_POSITIVE:
        return 0, 0
    return artifact.verified_breaches, artifact.replayed_breaches


def _report_artifact_record(artifact: TargetExecutionArtifact) -> Dict[str, Any]:
    """
    The per-target execution record as the report presents it.

    The record of an execution that did **not** complete never carries a
    negative finding: its detection is ``None`` and its breach counters are
    zero. The raw claim of the producer is preserved under ``producer_*`` - the
    hashed artifact file on disk stays untouched.

    The detail row and this record use **one** rule: the detection comes from
    ``resolve_detection()``, the counters are the raw ones only for a positive
    finding, and the raw claim is preserved whenever the presented value
    differs from the raw one.
    """
    record = artifact.to_dict()
    detected, detection_state = resolve_detection(artifact)
    verified, replayed = _presented_breach_counters(artifact, detection_state)

    raw_detected = record.get("detected")
    raw_verified = record.get("verified_breaches")
    raw_replayed = record.get("replayed_breaches")

    if detected != raw_detected:
        # The producer claimed something else: the claim is kept, and it is
        # never presented as a finding.
        record["producer_detected"] = raw_detected

    if detection_state != DETECTION_STATE_POSITIVE:
        # The counters are zeroed by the presentation rule: the raw claim of
        # the producer is preserved, so that nothing is lost.
        record["producer_verified_breaches"] = raw_verified
        record["producer_replayed_breaches"] = raw_replayed

    record["detected"] = detected
    record["detection_state"] = detection_state
    record["verified_breaches"] = verified
    record["replayed_breaches"] = replayed
    return record


def evaluate_baseline_run(
    baseline_id: str,
    baseline_name: str,
    artifacts: List[TargetExecutionArtifact],
    ground_truth_map: Dict[str, GroundTruth]
) -> BaselineEvaluationResult:
    """
    Evaluates a completed set of target execution artifacts against authoritative ground truth.
    Strict fail-closed semantics:
    - If any target is UNAVAILABLE or FAILED or INCOMPLETE, the baseline cannot be scored.
    - Precision, recall, F1, FPR, FNR, VFR, ESR, RRR, and confusion matrix are strictly None.
    - Failed/unavailable targets are NEVER counted as negative detections: their detection
      is None and their detection state is NOT_EVALUATED - a run that did not complete
      produced no finding at all.
    - Cost metrics are only computed when every artifact provides real cost_usd.
    """
    total_targets = len(artifacts)
    completed_artifacts = [a for a in artifacts if a.status == ExecutionStatus.SUCCESS]
    unavailable_artifacts = [a for a in artifacts if a.status == ExecutionStatus.UNAVAILABLE]
    failed_artifacts = [a for a in artifacts if a.status == ExecutionStatus.FAILED]
    # A completed execution whose verdict says that the audit itself failed
    # (INFRA_ERROR) did not produce a valid conclusion either: it is not
    # scorable, and it is never a negative finding.
    invalid_artifacts = [
        a for a in completed_artifacts if resolve_detection(a)[0] is None
    ]

    if total_targets == 0:
        # A run without a target has no metric at all.  It is not scorable,
        # and it adds no 'Infinity' to the report.
        return BaselineEvaluationResult(
            baseline_id=baseline_id,
            baseline_name=baseline_name,
            status=ExecutionStatus.INCOMPLETE,
            status_reason=(
                "Baseline execution incomplete: the run contains no target at all"
            ),
            total_targets=0,
            completed_targets=0,
            target_artifacts=[],
            details=[],
        )

    # Generate details for backward-compatible summary and inspection
    details = []
    for a in artifacts:
        gt = ground_truth_map.get(a.target_id)
        is_vuln = gt.is_vulnerable if gt else False
        # Fail-closed: a run that did not complete - or that did not produce a
        # valid evaluation - has no finding at all. The verdict branch of a
        # completed run stays negative.
        det, detection_state = resolve_detection(a)
        # The breach counters follow the same rule as the report record: the
        # raw ones only for a positive finding.
        verified, replayed = _presented_breach_counters(a, detection_state)
        details.append({
            "target_id": a.target_id,
            "is_vulnerable": is_vuln,
            "detected": det,
            "detection_state": detection_state,
            "orchestration_status": getattr(a, "orchestration_status", a.status.value),
            "generation_outcome": getattr(a, "generation_outcome", "NOT_RUN"),
            "evm_outcome": getattr(a, "evm_outcome", "NOT_RUN"),
            "security_verdict": a.security_verdict,
            "replay_status": a.replay_status,
            "persistence_status": a.persistence_status,
            "candidates_generated": a.candidates_generated,
            "verified_breaches": verified,
            "replayed_breaches": replayed,
            "duration_seconds": round(a.duration_seconds, 3),
            "cost_usd": a.cost_usd,
            "status": a.status.value,
        })

    # Fail-closed check: if NOT ALL targets succeeded - or one of them produced
    # no valid evaluation at all - the baseline is non-scorable
    if len(completed_artifacts) != total_targets or invalid_artifacts:
        if len(unavailable_artifacts) == total_targets:
            reasons = list(dict.fromkeys(a.unavailable_reason or "Tool unavailable" for a in unavailable_artifacts))
            status = ExecutionStatus.UNAVAILABLE
            reason_str = f"All {total_targets} targets unavailable: {'; '.join(reasons)}"
        elif len(failed_artifacts) == total_targets:
            reasons = list(dict.fromkeys(a.unavailable_reason or "Execution failed" for a in failed_artifacts))
            status = ExecutionStatus.FAILED
            reason_str = f"All {total_targets} target runs encountered execution failures: {'; '.join(reasons)}"
        else:
            status = ExecutionStatus.INCOMPLETE
            reasons = []
            if unavailable_artifacts:
                reasons.append(f"{len(unavailable_artifacts)} unavailable")
            if failed_artifacts:
                reasons.append(f"{len(failed_artifacts)} failed")
            if invalid_artifacts:
                reasons.append(f"{len(invalid_artifacts)} without a valid evaluation")
            reason_str = f"Baseline execution incomplete: {len(completed_artifacts)}/{total_targets} succeeded ({', '.join(reasons)})"

        return BaselineEvaluationResult(
            baseline_id=baseline_id,
            baseline_name=baseline_name,
            status=status,
            status_reason=reason_str,
            total_targets=total_targets,
            completed_targets=len(completed_artifacts),
            target_artifacts=[_report_artifact_record(a) for a in artifacts],
            details=details,
        )

    # All targets succeeded! Calculate confusion matrix and metrics strictly from actual results against ground truth
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    total_candidates = 0
    total_verified = 0
    total_replayed = 0
    total_duration = 0.0
    all_costs_present = True
    total_cost = 0.0

    for art in artifacts:
        gt = ground_truth_map.get(art.target_id)
        if gt is None:
            raise KeyError(f"Target {art.target_id} lacks authoritative ground truth entry.")

        is_vuln = gt.is_vulnerable
        # P0 Guarantee: Compilation error, runtime revert, format error, a
        # rejected cheatcode attempt and a safe run must NEVER count as a
        # positive breach. A target without a valid evaluation never reaches
        # this loop - the fail-closed check above filtered it out.
        detected, detection_state = resolve_detection(art)
        if detected is None:  # pragma: no cover - guarded by the check above
            raise ValueError(
                f"Target {art.target_id} has no valid evaluation but reached the "
                "confusion matrix"
            )

        if is_vuln and detected:
            tp += 1
        elif not is_vuln and detected:
            fp += 1
        elif not is_vuln and not detected:
            tn += 1
        elif is_vuln and not detected:
            fn += 1

        # The aggregate counts the **presented** counters - the metric and the
        # per-target rows cannot disagree.
        verified, replayed = _presented_breach_counters(art, detection_state)
        total_candidates += art.candidates_generated
        total_verified += verified
        total_replayed += replayed
        total_duration += art.duration_seconds
        if art.cost_usd is not None:
            total_cost += art.cost_usd
        else:
            all_costs_present = False

    total_actual_p = tp + fn
    total_actual_n = tn + fp
    total_predicted_p = tp + fp

    precision = round(tp / total_predicted_p, 4) if total_predicted_p > 0 else 0.0
    recall = round(tp / total_actual_p, 4) if total_actual_p > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    fpr = round(fp / total_actual_n, 4) if total_actual_n > 0 else 0.0
    fnr = round(fn / total_actual_p, 4) if total_actual_p > 0 else 0.0

    verified_finding_rate = round(total_verified / total_actual_p, 4) if total_actual_p > 0 else 0.0
    exploit_success_rate = round(total_verified / total_candidates, 4) if total_candidates > 0 else 0.0
    replay_rate = round(total_replayed / total_verified, 4) if total_verified > 0 else 0.0

    if total_verified > 0:
        candidates_per_verified = round(total_candidates / total_verified, 2)
    else:
        candidates_per_verified = float("inf")

    avg_duration = round(total_duration / max(1, total_targets), 3)
    avg_cost = round(total_cost / max(1, total_targets), 4) if all_costs_present else None

    return BaselineEvaluationResult(
        baseline_id=baseline_id,
        baseline_name=baseline_name,
        status=ExecutionStatus.SUCCESS,
        status_reason=None,
        total_targets=total_targets,
        completed_targets=len(completed_artifacts),
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        exploit_success_rate=exploit_success_rate,
        verified_finding_rate=verified_finding_rate,
        replay_reproducibility_rate=replay_rate,
        candidates_per_verified_finding=candidates_per_verified,
        average_duration_seconds=avg_duration,
        estimated_cost_usd_per_target=avg_cost,
        target_artifacts=[_report_artifact_record(a) for a in artifacts],
        details=details,
    )
