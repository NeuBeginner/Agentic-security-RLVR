from core.schemas import ExecutionResult, ExploitPayload, VerificationVerdict
from core.config import config


def evaluate_execution_trace(payload: ExploitPayload, result: ExecutionResult) -> VerificationVerdict:
    """
    Computes a deterministic, verifiable reward score based on structured execution feedback.
    This serves as the RLVR ground-truth signal.
    """
    # 1. Check for timeout
    if result.timed_out:
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_TIMEOUT,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"Execution timed out after {result.execution_time_sec:.1f}s. Possible infinite loop or deep recursion."
        )

    # 2. Check for confirmed invariant breach (Verified Exploit)
    if result.invariant_violated:
        logs_detail = f" Logs: {result.decoded_logs}" if result.decoded_logs else ""
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=True,
            reward_score=config.REWARD_INVARIANT_BREACH,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"SUCCESS: Invariant breached! Reproducible EVM exploit verified (test status: {result.test_status}).{logs_detail}"
        )

    # 3. Check for compilation or EVM revert failures
    if result.return_code != 0:
        if result.revert_reason:
            error_msg = f"EVM Revert: {result.revert_reason}"
        else:
            # Compiler or runtime error output sample
            raw_err = result.stderr if result.stderr.strip() else result.stdout
            error_msg = raw_err[:400].strip()

        logs_detail = f" | Logs: {result.decoded_logs}" if result.decoded_logs else ""
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_COMPILATION_FAIL,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"Execution Failed (exit code {result.return_code}): {error_msg}{logs_detail}"
        )

    # 4. Clean execution, but invariant was not breached
    return VerificationVerdict(
        target_name=payload.target_name,
        is_verified=False,
        reward_score=config.REWARD_SAFE_RUN,
        vulnerability_type=payload.hypothesis.vulnerability_type,
        poc_code=payload.test_code,
        feedback="Test ran cleanly without triggering any invariant breach or assertion error."
    )
