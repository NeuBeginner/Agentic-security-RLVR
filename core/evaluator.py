"""
core/evaluator.py

Multi-factor RLVR ground-truth reward evaluation and trajectory recording.
Enforces strict category separation:
- INFRA_ERROR (reward 0.0)
- GENERATION_FORMAT_ERROR (reward -0.5)
- COMPILATION_ERROR (reward -0.5)
- RUNTIME_REVERT (reward -0.25)
- SAFE_RUN (reward -0.1)
- CHEATCODE_DETECTED (reward -1.0)
- INVARIANT_BREACH_UNREPLAYED (reward +0.5, is_verified=False)
- EXPLOIT_CONFIRMED (reward +1.0, is_verified=True, strictly requires confirmed independent replay)
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


def evaluate_execution_trace(payload: ExploitPayload, result: ExecutionResult) -> VerificationVerdict:
    """
    Computes a deterministic, verifiable reward score based on multi-factor execution feedback.
    Categorizes errors cleanly into Infra, Format, Compilation, Runtime Revert, Unreplayed Breach, and Confirmed Exploit.
    Serves as the RLVR ground-truth signal for GRPO training.
    """
    # 0. Check for structural/format failure in model output (Format validation)
    if not payload.format_valid:
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_FORMAT_ERROR,
            category=ResultCategory.GENERATION_FORMAT_ERROR,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"GENERATION_FORMAT_ERROR: {payload.format_error_reason}",
            state_delta_verified=False,
            reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    # 1. Immediate rejection and severe penalty for cheatcode/sandbox tampering
    if result.cheatcode_detected or result.category == ResultCategory.CHEATCODE_DETECTED:
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_CHEATCODE_PENALTY,
            category=ResultCategory.CHEATCODE_DETECTED,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback="SECURITY VIOLATION: ExploitModule attempted to use Foundry cheatcodes (vm.*) or escape sandbox.",
            state_delta_verified=False,
            reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    # 2. Check for infrastructure failures (Harness setup / missing dependencies / toolchain crashes)
    # Infrastructure failures MUST NOT penalize the model (reward = 0.0)
    if result.category == ResultCategory.INFRA_ERROR:
        raw_infra_err = result.stderr if result.stderr.strip() else result.stdout
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_INFRA_ERROR,
            category=ResultCategory.INFRA_ERROR,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"INFRA_ERROR: Execution environment or harness failure: {raw_infra_err[:300].strip()}",
            state_delta_verified=False,
            reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    # 3. Check for execution timeout (DoS / out-of-gas / infinite loop)
    if result.timed_out:
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_TIMEOUT,
            category=ResultCategory.RUNTIME_REVERT,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"Execution timed out after {result.execution_time_sec:.1f}s. Possible out-of-gas or infinite recursion.",
            state_delta_verified=False,
            reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    # 4. Multi-Factor Invariant Verification
    verification = result.verification_result
    has_trusted_breach_evidence = (
        verification is not None
        and verification.invariant_breach is True
        and verification.confidence_status in {"PROVISIONAL_BREACH", "REPLAY_CONFIRMED"}
        and bool(verification.breached_invariants)
        and verification.evidence is not None
        and bool(verification.evidence.initial_state_hash)
        and bool(verification.evidence.final_state_hash)
        and any(not item.passed for item in verification.invariant_results)
    )
    is_genuine_breach = (
        result.invariant_violated and result.return_code == 0
        and (result.test_status in ("Success", None))
        and has_trusted_breach_evidence and not result.cheatcode_detected
    )
    claimed_breach_without_evidence = (
        (result.invariant_violated or result.reproducibility_confirmed
         or result.category in {
             ResultCategory.INVARIANT_BREACH_UNREPLAYED,
             ResultCategory.EXPLOIT_CONFIRMED
         }) and not is_genuine_breach
    )
    if claimed_breach_without_evidence:
        return VerificationVerdict(
            target_name=payload.target_name, is_verified=False,
            reward_score=config.REWARD_INFRA_ERROR, category=ResultCategory.INFRA_ERROR,
            vulnerability_type=payload.hypothesis.vulnerability_type, poc_code=payload.test_code,
            feedback="UNVERIFIED: breach claim has no authenticated state evidence; log strings are not proof.",
            state_delta_verified=False, reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    if is_genuine_breach:
        logs_detail = f" Logs: {result.decoded_logs}" if result.decoded_logs else ""
        
        # Award full reward (+1.0) and is_verified=True ONLY if reproducibility was confirmed in independent replay
        if result.reproducibility_confirmed:
            reward = config.REWARD_INVARIANT_BREACH
            feedback_msg = f"SUCCESS: Multi-factor verification passed and independently reproduced in clean EVM!{logs_detail}"
            is_verified = True
            cat = ResultCategory.EXPLOIT_CONFIRMED
            reproduced = True
        else:
            reward = config.REWARD_BREACH_NO_REPLAY
            feedback_msg = f"PARTIAL SUCCESS: Invariant breached in initial run, but independent replay unconfirmed.{logs_detail}"
            is_verified = False  # NOT marked as verified exploit until replay confirmation!
            cat = ResultCategory.INVARIANT_BREACH_UNREPLAYED
            reproduced = False

        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=is_verified,
            reward_score=reward,
            category=cat,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=feedback_msg,
            state_delta_verified=True,
            reproducible=reproduced,
            refinement_iteration=payload.attempt_number,
            evidence=result.evidence,
            verification_result=result.verification_result
        )

    # 5. Check for compilation or EVM runtime revert failures
    if result.return_code != 0:
        if result.revert_reason:
            error_msg = f"EVM Runtime Revert: {result.revert_reason}"
            reward = config.REWARD_RUNTIME_REVERT
            cat = ResultCategory.RUNTIME_REVERT
        else:
            raw_err = result.stderr if result.stderr.strip() else result.stdout
            error_msg = f"Compilation Error: {raw_err[:350].strip()}"
            reward = config.REWARD_COMPILATION_FAIL
            cat = ResultCategory.COMPILATION_ERROR

        logs_detail = f" | Logs: {result.decoded_logs}" if result.decoded_logs else ""
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=reward,
            category=cat,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"Execution Failed (exit code {result.return_code}): {error_msg}{logs_detail}",
            state_delta_verified=False,
            reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    # 6. Clean execution, but invariant was NOT breached (Safe run / No-op)
    return VerificationVerdict(
        target_name=payload.target_name,
        is_verified=False,
        reward_score=config.REWARD_SAFE_RUN,
        category=ResultCategory.SAFE_RUN,
        vulnerability_type=payload.hypothesis.vulnerability_type,
        poc_code=payload.test_code,
        feedback="Safe Execution: Test completed cleanly, but target contract maintained all security invariants.",
        state_delta_verified=False,
        reproducible=True,
        refinement_iteration=payload.attempt_number
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
        evidence=verdict.evidence,
        invariant_results=verdict.verification_result.invariant_results if verdict.verification_result else []
    )
