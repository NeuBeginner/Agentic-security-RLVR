from core.schemas import ExecutionResult, ExploitPayload, VerificationVerdict
from core.config import config


def evaluate_execution_trace(payload: ExploitPayload, result: ExecutionResult) -> VerificationVerdict:
    """
    Computes a deterministic, verifiable reward score based on structured execution feedback.
    Applies multi-factor invariant verification to eliminate false positives and sandbox tampering.
    This serves as the RLVR ground-truth signal.
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
            reproducible=False
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
            reproducible=False
        )

    # 3. Multi-Factor Invariant Verification (Verified 0-day Exploit)
    # Both the test runner must succeed (exit 0) AND the trusted invariant log must be present
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
        return VerificationVerdict(
            target_name=payload.target_name,
            is_verified=True,
            reward_score=config.REWARD_INVARIANT_BREACH,
            vulnerability_type=payload.hypothesis.vulnerability_type,
            poc_code=payload.test_code,
            feedback=f"SUCCESS: Multi-factor verification passed! Invariant breach proven in EVM (status: {result.test_status}).{logs_detail}",
            state_delta_verified=True,
            reproducible=True
        )

    # 4. Check for compilation or EVM runtime revert failures
    if result.return_code != 0:
        if result.revert_reason:
            # Compiled cleanly, but execution reverted in EVM (closer to exploit than compile error)
            error_msg = f"EVM Runtime Revert: {result.revert_reason}"
            reward = config.REWARD_RUNTIME_REVERT
        else:
            # solc compiler or syntax error
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
            reproducible=False
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
        reproducible=True
    )
