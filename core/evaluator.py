"""
core/evaluator.py

Multi-factor RLVR ground-truth reward evaluation and trajectory recording.
Enforces strict category separation:
- INFRA_ERROR (reward 0.0)
- GENERATION_FORMAT_ERROR (reward -0.35)
- COMPILATION_ERROR (reward -0.5)
- RUNTIME_REVERT (reward -0.25)
- SAFE_RUN (reward -0.1)
- CHEATCODE_DETECTED (reward -1.0)
- INVARIANT_BREACH_UNREPLAYED (reward +0.5, is_verified=False)
- EXPLOIT_CONFIRMED (reward +1.0, is_verified=True, strictly requires confirmed independent replay)

Reward Specification 2.0.0: every reward is decomposed into evidence-scoped
components (generation / compilation / verification / invariant / replay) plus a
single outcome penalty, and the specification version travels with the verdict
and the trajectory (see core/reward_shaping.py).

TRUSTED EVIDENCE: a breach is confirmed ONLY by the structured verdict of the
immutable, repository-owned harness. Log text is model-controllable and is
therefore never a source of evidence (see core/evidence.py).
"""

from __future__ import annotations

import uuid
import time
import hashlib
from core.schemas import (
    ExecutionResult,
    ExploitPayload,
    VerificationVerdict,
    TargetProgram,
    RLVRTrajectory,
    ResultCategory,
)
from core.config import config
from core.evidence import HarnessVerdict, is_trusted_breach_verdict
from core.reward_shaping import (
    RewardBreakdown,
    RewardEvidence,
    compute_reward_breakdown,
    REWARD_SPEC_VERSION,
)


def _build_verdict(
    payload: ExploitPayload,
    category: ResultCategory,
    evidence: RewardEvidence,
    feedback: str,
    is_verified: bool,
    reproducible: bool,
    state_delta_verified: bool = False,
) -> VerificationVerdict:
    """
    Assembles a verdict from a category and the proven evidence.

    The reward is computed by the shared reward specification, so the verdict
    carries the full attribution (components + penalty + spec version) and the
    total always equals sum(components) + penalty.
    """
    breakdown: RewardBreakdown = compute_reward_breakdown(category, evidence)
    return VerificationVerdict(
        target_name=payload.target_name,
        is_verified=is_verified,
        reward_score=breakdown.total,
        category=category,
        vulnerability_type=payload.hypothesis.vulnerability_type,
        poc_code=payload.test_code,
        feedback=f"{feedback} | {breakdown.describe()}",
        state_delta_verified=state_delta_verified,
        reproducible=reproducible,
        refinement_iteration=payload.attempt_number,
        reward_components=dict(breakdown.components),
        reward_penalty=breakdown.penalty,
        reward_spec_version=breakdown.spec_version,
    )


def evaluate_execution_trace(payload: ExploitPayload, result: ExecutionResult) -> VerificationVerdict:
    """
    Computes a deterministic, verifiable reward score based on multi-factor execution feedback.
    Categorizes errors cleanly into Infra, Format, Compilation, Runtime Revert, Unreplayed Breach, and Confirmed Exploit.
    Serves as the RLVR ground-truth signal for GRPO training.
    """
    # 0. Check for structural/format failure in model output (Format validation)
    if not payload.format_valid:
        return _build_verdict(
            payload,
            ResultCategory.GENERATION_FORMAT_ERROR,
            RewardEvidence(),
            f"GENERATION_FORMAT_ERROR: {payload.format_error_reason}",
            is_verified=False,
            reproducible=False,
        )

    # 1. Immediate rejection and severe penalty for cheatcode/sandbox tampering
    if result.cheatcode_detected or result.category == ResultCategory.CHEATCODE_DETECTED:
        return _build_verdict(
            payload,
            ResultCategory.CHEATCODE_DETECTED,
            RewardEvidence(),
            "SECURITY VIOLATION: ExploitModule attempted to use Foundry cheatcodes (vm.*) or escape sandbox.",
            is_verified=False,
            reproducible=False,
        )

    # 2. Check for infrastructure failures (Harness setup / missing dependencies / toolchain crashes)
    # Infrastructure failures MUST NOT penalize the model (reward = 0.0)
    if result.category == ResultCategory.INFRA_ERROR:
        raw_infra_err = result.stderr if result.stderr.strip() else result.stdout
        return _build_verdict(
            payload,
            ResultCategory.INFRA_ERROR,
            RewardEvidence(),
            f"INFRA_ERROR: Execution environment or harness failure: {raw_infra_err[:300].strip()}",
            is_verified=False,
            reproducible=False,
        )

    # 3. Check for execution timeout (DoS / out-of-gas / infinite loop)
    if result.timed_out:
        return _build_verdict(
            payload,
            ResultCategory.RUNTIME_REVERT,
            RewardEvidence(
                format_valid=True,
                compiled=True,
                executed=False,
                timed_out=True,
            ),
            f"Execution timed out after {result.execution_time_sec:.1f}s. Possible out-of-gas or infinite recursion.",
            is_verified=False,
            reproducible=False,
        )

    # 4. Multi-Factor Invariant Verification (TRUSTED EVIDENCE ONLY)
    # The breach is confirmed ONLY by the structured verdict of the immutable,
    # repository-owned harness. The log marker is deliberately NOT consulted:
    # the exploit itself can print arbitrary text, so log text can never be
    # evidence for a confirmed vulnerability.
    trusted_breach = (
        result.invariant_violated
        and result.return_code == 0
        and result.test_status == "Success"
        and not result.cheatcode_detected
        and is_trusted_breach_verdict(result.harness_verdict)
    )

    if trusted_breach:
        logs_detail = f" Logs: {result.decoded_logs}" if result.decoded_logs else ""
        verdict_source = result.harness_suite or "trusted_harness"

        # Award full reward (+1.0) and is_verified=True ONLY if reproducibility was confirmed in independent replay
        if result.reproducibility_confirmed:
            return _build_verdict(
                payload,
                ResultCategory.EXPLOIT_CONFIRMED,
                RewardEvidence(
                    format_valid=True,
                    compiled=True,
                    executed=True,
                    invariant_confirmed=True,
                    replay_confirmed=True,
                ),
                f"SUCCESS: Multi-factor verification passed and independently reproduced in clean EVM!{logs_detail}",
                is_verified=True,
                reproducible=True,
                state_delta_verified=True,
            )

        return _build_verdict(
            payload,
            ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            RewardEvidence(
                format_valid=True,
                compiled=True,
                executed=True,
                invariant_confirmed=True,
                replay_confirmed=False,
            ),
            f"PARTIAL SUCCESS: Invariant breached in initial run (trusted verdict: {verdict_source}), but independent replay unconfirmed.{logs_detail}",
            is_verified=False,  # NOT marked as verified exploit until replay confirmation!
            reproducible=False,
            state_delta_verified=True,
        )

    # 5. Check for compilation or EVM runtime revert failures
    if result.return_code != 0:
        if result.revert_reason:
            error_msg = f"EVM Runtime Revert: {result.revert_reason}"
            category = ResultCategory.RUNTIME_REVERT
        else:
            raw_err = result.stderr if result.stderr.strip() else result.stdout
            error_msg = f"Compilation Error: {raw_err[:350].strip()}"
            category = ResultCategory.COMPILATION_ERROR

        logs_detail = f" | Logs: {result.decoded_logs}" if result.decoded_logs else ""
        compiled = category == ResultCategory.RUNTIME_REVERT
        return _build_verdict(
            payload,
            category,
            RewardEvidence(
                format_valid=True,
                compiled=compiled,
                executed=False,
            ),
            f"Execution Failed (exit code {result.return_code}): {error_msg}{logs_detail}",
            is_verified=False,
            reproducible=False,
        )

    # 6. Clean execution, but invariant was NOT breached (Safe run / No-op)
    return _build_verdict(
        payload,
        ResultCategory.SAFE_RUN,
        RewardEvidence(
            format_valid=True,
            compiled=True,
            executed=True,
        ),
        "Safe Execution: Test completed cleanly, but target contract maintained all security invariants.",
        is_verified=False,
        reproducible=True,
    )


def create_trajectory_record(
    target: TargetProgram,
    payload: ExploitPayload,
    verdict: VerificationVerdict,
    prompt_used: str = "",
    dataset_split: str = "train",
    dataset_partition: str = "production",
    is_synthetic: bool = False,
    token_provenance: str = "model_generate",
    trainable: bool = True
) -> RLVRTrajectory:
    """Packages the verified execution trajectory for GRPO fine-tuning (Round 4/5.2)."""
    cand_id = payload.candidate_id or (verdict.candidate_id or str(uuid.uuid4())[:8])
    run_id = payload.run_id or (verdict.run_id or "run-default")
    p_text = prompt_used or target.source_code
    prompt_hash = hashlib.sha256(" ".join(p_text.strip().split()).encode("utf-8")).hexdigest()

    rep_status = verdict.replay_status
    if verdict.category == ResultCategory.EXPLOIT_CONFIRMED and verdict.reproducible and rep_status == "NOT_ELIGIBLE":
        rep_status = "CONFIRMED"

    # Enforce provenance invariants
    tok_prov = token_provenance
    if is_synthetic:
        tok_prov = "synthetic"
        trainable = False
        if dataset_partition == "production":
            dataset_partition = "synthetic_control"
    elif payload.generated_token_ids is None or len(payload.generated_token_ids) == 0:
        tok_prov = "external_text_only"

    if verdict.category == ResultCategory.INFRA_ERROR:
        trainable = False

    return RLVRTrajectory(
        trajectory_id=f"traj_{run_id}_{cand_id}",
        candidate_id=cand_id,
        run_id=run_id,
        timestamp=time.time(),
        target_name=target.name,
        target_code=target.source_code,
        prompt_hash=prompt_hash,
        generation_iteration=payload.generation_iteration,
        candidate_index=payload.candidate_index,
        is_finalized=True,
        replay_status=rep_status,
        slither_hints=target.slither_findings,
        prompt_used=prompt_used,
        hypothesis=payload.hypothesis,
        full_completion_text=payload.raw_model_response or payload.test_code,
        generated_exploit=payload.test_code,
        reward=verdict.reward_score,
        category=verdict.category,
        is_verified=verdict.is_verified,
        reproduced=verdict.reproducible,
        feedback_trace=verdict.feedback,
        dataset_split=dataset_split,
        dataset_partition=dataset_partition,
        is_synthetic=is_synthetic,
        token_provenance=tok_prov,
        trainable=trainable,
        generated_token_ids=payload.generated_token_ids,
        contract_name_normalized=payload.contract_name_normalized,
        original_contract_name=payload.original_contract_name,
        contract_normalization_reason=payload.contract_normalization_reason,
        reward_components=dict(verdict.reward_components or {}),
        reward_penalty=verdict.reward_penalty,
        reward_spec_version=verdict.reward_spec_version or REWARD_SPEC_VERSION,
    )
