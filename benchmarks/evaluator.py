"""
benchmarks/evaluator.py

Independent Post-Execution Evaluator for Aegis-RLVR Benchmarks.
Consumes execution artifacts and private GroundTruth to calculate empirical confusion matrices.
Guarantees:
- Ground truth is strictly inaccessible during execution.
- If a baseline was UNAVAILABLE or INCOMPLETE, metrics are NOT computed (set to None),
  prohibiting the presentation of synthetic or misleading 0% / 100% metrics.
- Mathematical consistency across TP, FP, TN, FN, Precision, Recall, F1, FPR, and FNR.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from benchmarks.protocol import (
    TargetExecutionArtifact,
    GroundTruth,
    BaselineEvaluationResult,
    ExecutionStatus,
)


def evaluate_baseline_run(
    baseline_id: str,
    baseline_name: str,
    artifacts: List[TargetExecutionArtifact],
    ground_truth_map: Dict[str, GroundTruth]
) -> BaselineEvaluationResult:
    """
    Evaluates a completed set of target execution artifacts against authoritative ground truth.
    """
    total_targets = len(artifacts)
    completed_artifacts = [a for a in artifacts if a.status == ExecutionStatus.SUCCESS]
    unavailable_artifacts = [a for a in artifacts if a.status == ExecutionStatus.UNAVAILABLE]
    failed_artifacts = [a for a in artifacts if a.status == ExecutionStatus.FAILED]

    # Generate details for backward-compatible summary and inspection
    details = []
    for a in artifacts:
        gt = ground_truth_map.get(a.target_id)
        is_vuln = gt.is_vulnerable if gt else False
        details.append({
            "target_id": a.target_id,
            "is_vulnerable": is_vuln,
            "detected": a.detected,
            "candidates_generated": a.candidates_generated,
            "verified_breaches": a.verified_breaches,
            "replayed_breaches": a.replayed_breaches,
            "duration_seconds": round(a.duration_seconds, 3),
            "cost_usd": a.cost_usd,
        })

    # If any artifact was unavailable, the baseline cannot be scored empirically
    if unavailable_artifacts:
        reasons = list(dict.fromkeys(a.unavailable_reason or "Tool unavailable" for a in unavailable_artifacts))
        reason_str = "; ".join(reasons)
        status = ExecutionStatus.UNAVAILABLE if len(completed_artifacts) == 0 else ExecutionStatus.INCOMPLETE
        return BaselineEvaluationResult(
            baseline_id=baseline_id,
            baseline_name=baseline_name,
            status=status,
            status_reason=f"Baseline execution incomplete: {len(unavailable_artifacts)}/{total_targets} targets unavailable ({reason_str})",
            total_targets=total_targets,
            completed_targets=len(completed_artifacts),
            target_artifacts=[a.to_dict() for a in artifacts],
            details=details,
        )

    if failed_artifacts and not completed_artifacts:
        return BaselineEvaluationResult(
            baseline_id=baseline_id,
            baseline_name=baseline_name,
            status=ExecutionStatus.FAILED,
            status_reason=f"All {len(failed_artifacts)} target runs encountered execution failures.",
            total_targets=total_targets,
            completed_targets=0,
            target_artifacts=[a.to_dict() for a in artifacts],
            details=details,
        )

    # Accumulate confusion matrix strictly from actual results against ground truth
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    total_candidates = 0
    total_verified = 0
    total_replayed = 0
    total_duration = 0.0
    total_cost = 0.0

    for art in artifacts:
        gt = ground_truth_map.get(art.target_id)
        if gt is None:
            raise KeyError(f"Target {art.target_id} lacks authoritative ground truth entry.")

        is_vuln = gt.is_vulnerable
        detected = art.detected

        if is_vuln and detected:
            tp += 1
        elif not is_vuln and detected:
            fp += 1
        elif not is_vuln and not detected:
            tn += 1
        elif is_vuln and not detected:
            fn += 1

        total_candidates += art.candidates_generated
        total_verified += art.verified_breaches
        total_replayed += art.replayed_breaches
        total_duration += art.duration_seconds
        total_cost += art.cost_usd

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
    avg_cost = round(total_cost / max(1, total_targets), 4)

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
        target_artifacts=[a.to_dict() for a in artifacts],
        details=details,
    )
