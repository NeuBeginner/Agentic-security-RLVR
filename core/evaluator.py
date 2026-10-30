from core.schemas import ExecutionResult, ExploitPayload, VerificationVerdict
from core.config import config


def evaluate_execution_trace(payload: ExploitPayload, result: ExecutionResult) -> VerificationVerdict:
    """
    Computes a deterministic, verifiable reward score based on execution feedback.
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
            feedback=f"Execution timed out after {result.execution_time_sec:.1f}s. Possible infinite loop."
        )

    # 2. Check for compilation or syntax errors
    if result.return_code != 0 and not result.invariant_violated:
        error_sample = (result.stderr or result.stdout)[:300]
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=False,
            reward_score=config.REWARD_COMPILATION_FAIL,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"Execution/Compilation error (exit code {result.return_code}): {error_sample}"
        )

    # 3. Check for confirmed invariant breach (Verified Exploit)
    # The sandbox checks stdout/stderr for explicit invariant violation signatures
    is_breached = (
        result.invariant_violated or 
        "[INVARIANT_BREACHED]" in result.stdout or 
        "AssertionError: [INVARIANT_BREACHED]" in result.stderr
    )

    if is_breached:
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=True,
            reward_score=config.REWARD_INVARIANT_BREACH,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback="SUCCESS: Invariant breached! Reproducible exploit confirmed in sandbox."
        )

    # 4. Program ran cleanly, but exploit failed to breach the security property
    return VerificationVerdict(
        target_name=payload.target_name,
        is_verified=False,
        reward_score=config.REWARD_SAFE_RUN,
        vulnerability_type=payload.hypothesis.vulnerability_type,
        poc_code=payload.test_code,
        feedback="Test ran without triggering any invariant violations. Exploit attempt unsuccessful."
    )
