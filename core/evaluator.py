import uuid
import time
from core.schemas import ExecutionResult, ExploitPayload, VerificationVerdict, TargetProgram, RLVRTrajectory
from core.config import config


def evaluate_execution_trace(payload: ExploitPayload, result: ExecutionResult) -> VerificationVerdict:
    """
    Computes a deterministic, verifiable reward score based on multi-factor execution feedback.
    Applies strict invariant verification and independent reproducibility confirmation.
    This serves as the RLVR ground-truth signal for GRPO training.
    """
    # 1. Immediate rejection and severe penalty for cheatcode/sandbox tampering
    if result.cheatcode_detected:
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_CHEATCODE_PENALTY,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback="SECURITY VIOLATION: ExploitModule attempted to use Foundry cheatcodes (vm.*) or unprivileged test environments.",
            state_delta_verified=False,
            reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    # 2. Check for execution timeout (DoS / out-of-gas / infinite loop)
    if result.timed_out:
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_TIMEOUT,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"Execution timed out after {result.execution_time_sec:.1f}s. Possible out-of-gas or infinite recursion.",
            state_delta_verified=False,
            reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    # 3. Multi-Factor Invariant Verification (Verified 0-day Exploit)
    has_valid_breach_log = any("[INVARIANT_BREACHED" in str(log) for log in result.decoded_logs)
    is_genuine_breach = (
        result.invariant_violated and
        result.return_code == 0 and
        result.test_status == "Success" and
        has_valid_breach_log and
        not result.cheatcode_detected
    )

    if is_genuine_breach:
        logs_detail = f" Logs: {result.decoded_logs}" if result.decoded_logs else ""
        
        # Award full reward ONLY if reproducibility in an independent run was confirmed
        if result.reproducibility_confirmed:
            reward = config.REWARD_INVARIANT_BREACH
            feedback_msg = f"SUCCESS: Multi-factor verification passed and independently reproduced in clean EVM!{logs_detail}"
            reproduced = True
        else:
            reward = config.REWARD_BREACH_NO_REPLAY
            feedback_msg = f"PARTIAL SUCCESS: Invariant breached, but awaiting independent reproducibility check.{logs_detail}"
            reproduced = False

        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=True,
            reward_score=reward,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=feedback_msg,
            state_delta_verified=True,
            reproducible=reproduced,
            refinement_iteration=payload.attempt_number
        )

    # 4. Check for compilation or EVM runtime revert failures
    if result.return_code != 0:
        if result.revert_reason:
            error_msg = f"EVM Runtime Revert: {result.revert_reason}"
            reward = config.REWARD_RUNTIME_REVERT
        else:
            raw_err = result.stderr if result.stderr.strip() else result.stdout
            error_msg = f"Compilation Error: {raw_err[:350].strip()}"
            reward = config.REWARD_COMPILATION_FAIL

        logs_detail = f" | Logs: {result.decoded_logs}" if result.decoded_logs else ""
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=reward,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"Execution Failed (exit code {result.return_code}): {error_msg}{logs_detail}",
            state_delta_verified=False,
            reproducible=False,
            refinement_iteration=payload.attempt_number
        )

    # 5. Clean execution, but invariant was NOT breached (Safe run / No-op)
    return VerificationVerdict(
        target_name=payload.target_name,
        is_verified=False,
        reward_score=config.REWARD_SAFE_RUN,
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
    prompt_used: str = ""
) -> RLVRTrajectory:
    """Packages the verified execution trajectory for GRPO fine-tuning."""
    return RLVRTrajectory(
        trajectory_id=str(uuid.uuid4()),
        timestamp=time.time(),
        target_name=target.name,
        target_code=target.source_code,
        slither_hints=target.slither_findings,
        prompt_used=prompt_used,
        hypothesis=payload.hypothesis,
        generated_exploit=payload.test_code,
        reward=verdict.reward_score,
        is_verified=verdict.is_verified,
        reproduced=verdict.reproducible,
        feedback_trace=verdict.feedback
    )
