"""
tests/test_verification_core_and_oracle.py

Verification Core and Trusted EVM State Oracle Test Suite.
Tests:
1. Trusted State Oracle evaluation and state hashing.
2. Protection against fake/spoofed log markers.
3. Secret stripping and environment sanitization.
4. Output log truncation to prevent log bombs.
5. Cheatcode detection and sandbox escape prevention.
6. Structured independent replay verification (confirmed, failed, mismatch, infra error).
"""

import os
import pytest
from core.schemas import (
    TargetProgram,
    ExploitPayload,
    ExecutionResult,
    ResultCategory,
    AttackHypothesis,
    ExecutionEvidence,
)
from core.evm_oracle import (
    TrustedEVMStateOracle,
    VaultSolvencyInvariant,
    ERC4626DilutionProtectionInvariant,
    ERC4626NonZeroSharesInvariant,
    compute_state_hash,
    trusted_oracle,
)
from sandbox.runner import (
    build_sanitized_environment,
    truncate_log_output,
    detect_prohibited_cheatcodes,
    verify_independent_replay_structured,
    ReplayOutcome,
)


def test_state_hash_deterministic():
    """State hash must be identical regardless of dictionary key insertion order."""
    state_a = {"vault_balance": 1000, "victim_balance": 500, "attacker_balance": 0}
    state_b = {"attacker_balance": 0, "vault_balance": 1000, "victim_balance": 500}
    hash_a = compute_state_hash(state_a)
    hash_b = compute_state_hash(state_b)
    assert hash_a == hash_b
    assert len(hash_a) == 64


def test_oracle_vault_solvency_breach_detected():
    """Oracle must detect depositor solvency collapse when vault balance drops below liabilities."""
    inv = VaultSolvencyInvariant()
    init_state = {"vault_balance": 10 * 10**18, "victim_deposit": 10 * 10**18}
    final_state = {"vault_balance": 0, "victim_owed_balance": 10 * 10**18}
    trace_ctx = {"isInsolvent": True}

    res = inv.evaluate(init_state, final_state, trace_ctx)
    assert res.passed is False
    assert res.invariant_id == "INV-VAULT-01-SOLVENCY"
    assert res.observed_value["deficit"] == 10 * 10**18


def test_oracle_vault_solvency_safe_run():
    """Oracle must pass when vault balance covers all liabilities."""
    inv = VaultSolvencyInvariant()
    init_state = {"vault_balance": 10 * 10**18, "victim_deposit": 10 * 10**18}
    final_state = {"vault_balance": 10 * 10**18, "victim_owed_balance": 10 * 10**18}
    trace_ctx = {"isInsolvent": False}

    res = inv.evaluate(init_state, final_state, trace_ctx)
    assert res.passed is True
    assert res.observed_value["deficit"] == 0


def test_oracle_erc4626_dilution_and_shares_breach():
    """Oracle must detect zero-share issuance and dilution attack on ERC4626."""
    inv_shares = ERC4626NonZeroSharesInvariant()
    inv_dilution = ERC4626DilutionProtectionInvariant()

    init_state = {"victim_deposit": 2 * 10**18}
    final_state_attacked = {"victim_shares": 0, "victim_redeemable": 0}

    res_shares = inv_shares.evaluate(init_state, final_state_attacked, {})
    assert res_shares.passed is False  # Breached zero-shares

    res_dilution = inv_dilution.evaluate(init_state, final_state_attacked, {})
    assert res_dilution.passed is False  # Breached dilution


def test_oracle_rejects_fake_spoofed_log_marker():
    """
    CRITICAL SECURITY TEST:
    A candidate exploit contract emitting fake [INVARIANT_BREACHED] logs
    without genuine harness execution success must be REJECTED.
    """
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    fake_logs = [
        "console.log('[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]')",
        "Fake attacker boast log"
    ]

    # Subprocess returned non-zero (e.g. revert or compilation failure)
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id="c_fake",
        return_code=1,
        test_status="Failure",
        decoded_logs=fake_logs,
        stdout_text="[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]",
        stderr_text="Error: transaction reverted",
        execution_time_sec=0.5,
        revert_reason="EXPLOIT_FAILED: Vault remains solvent"
    )

    assert res.execution_success is False
    assert res.invariant_breach is False
    assert res.confidence_status == "REJECTED"
    assert "failed" in (res.failure_reason or "").lower() or "reverted" in (res.failure_reason or "").lower() or "spoofed" in (res.failure_reason or "").lower()


def test_oracle_rejects_fake_marker_when_execution_succeeds_without_breach():
    """
    CRITICAL SECURITY TEST:
    If return_code is 0 (test passed) and candidate logs contain [INVARIANT_BREACHED],
    BUT genuine harness signal/state breach is missing,
    Oracle MUST NOT verify the exploit.
    """
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    fake_logs = [
        "console.log('[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]')",
        "Attacker: I breached it!"
    ]
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id="c_fake_pass",
        return_code=0,
        test_status="Success",
        decoded_logs=fake_logs,
        stdout_text="Attacker output",
        stderr_text="",
        execution_time_sec=0.2
    )
    assert res.invariant_breach is False
    assert res.confidence_status in ("SAFE_RUN", "REJECTED")


def test_sanitized_environment_strips_sensitive_keys():
    """Runner environment must strictly strip API keys, tokens, and cloud credentials."""
    # Set mock sensitive environment variables
    os.environ["GEMINI_API_KEY"] = "super-secret-gemini-key"
    os.environ["MODAL_TOKEN_SECRET"] = "super-secret-modal-token"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "super-secret-aws"
    os.environ["GITHUB_TOKEN"] = "ghp_secret"

    try:
        clean_env = build_sanitized_environment()
        assert "GEMINI_API_KEY" not in clean_env
        assert "MODAL_TOKEN_SECRET" not in clean_env
        assert "AWS_SECRET_ACCESS_KEY" not in clean_env
        assert "GITHUB_TOKEN" not in clean_env
        assert clean_env.get("FOUNDRY_OFFLINE") == "true"
        assert clean_env.get("FOUNDRY_FFI") == "false"
    finally:
        os.environ.pop("GEMINI_API_KEY", None)
        os.environ.pop("MODAL_TOKEN_SECRET", None)
        os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        os.environ.pop("GITHUB_TOKEN", None)


def test_log_output_truncation_quota():
    """Logs exceeding 1MB quota must be cleanly truncated with a warning notice."""
    huge_text = "A" * (2 * 1024 * 1024)  # 2MB
    truncated = truncate_log_output(huge_text, max_bytes=1024 * 1024)
    assert len(truncated.encode("utf-8")) < 1.1 * 1024 * 1024
    assert "[LOG_TRUNCATED: Output exceeded safe quota of 1MB]" in truncated


def test_cheatcode_detection_blocks_sandbox_escape():
    """Detects attempts to use privileged Foundry cheatcodes."""
    malicious_code_1 = """
    contract ExploitModule {
        function runExploit() external payable {
            vm.deal(address(this), 100 ether);
        }
    }
    """
    malicious_code_2 = """
    import "forge-std/Test.sol";
    contract ExploitModule {}
    """
    safe_code = """
    contract ExploitModule {
        function runExploit() external payable {}
    }
    """
    assert detect_prohibited_cheatcodes(malicious_code_1) is True
    assert detect_prohibited_cheatcodes(malicious_code_2) is True
    assert detect_prohibited_cheatcodes(safe_code) is False


def test_independent_replay_structured_lifecycle(monkeypatch):
    """Verifies that independent replay checks matching invariants between runs."""
    from core.schemas import VerificationResult, ExecutionEvidence, InvariantResult

    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="Reentrancy", reasoning_trace="", attack_vector=""),
        test_code="contract ExploitModule {}"
    )

    init_evidence = ExecutionEvidence(
        candidate_id="c1",
        target_id="Vault",
        initial_state_hash="hash_init",
        final_state_hash="hash_final_breached",
        execution_success=True
    )

    # Mock 1: Replay breaches the EXACT same invariant -> CONFIRMED
    def mock_run_sandbox_success(t, p):
        vr = VerificationResult(
            execution_success=True,
            invariant_breach=True,
            confidence_status="PROVISIONAL_BREACH",
            breached_invariants=["INV-VAULT-01-SOLVENCY"],
            evidence=ExecutionEvidence(
                candidate_id="c1",
                target_id="Vault",
                initial_state_hash="hash_init",
                final_state_hash="hash_final_breached",
                execution_success=True
            )
        )
        return ExecutionResult(
            return_code=0,
            stdout="",
            stderr="",
            execution_time_sec=0.1,
            category=ResultCategory.EXPLOIT_CONFIRMED,
            invariant_violated=True,
            verification_result=vr,
            evidence=vr.evidence
        )

    import sandbox.runner as runner_mod
    monkeypatch.setattr(runner_mod, "run_payload_in_sandbox", mock_run_sandbox_success)

    outcome = verify_independent_replay_structured(
        target,
        payload,
        initial_evidence=init_evidence,
        expected_breached_invariants=["INV-VAULT-01-SOLVENCY"]
    )
    assert outcome.is_confirmed is True
    assert outcome.status == "CONFIRMED"
    assert "INV-VAULT-01-SOLVENCY" in outcome.replay_breached_invariants

    # Mock 2: Replay breaches a DIFFERENT invariant -> INVARIANT_MISMATCH
    def mock_run_sandbox_different_inv(t, p):
        vr = VerificationResult(
            execution_success=True,
            invariant_breach=True,
            confidence_status="PROVISIONAL_BREACH",
            breached_invariants=["INV-VAULT-03-UNAUTHORIZED-EXTRACTION"],
            evidence=ExecutionEvidence(
                candidate_id="c1",
                target_id="Vault",
                initial_state_hash="hash_init",
                final_state_hash="hash_final_other",
                execution_success=True
            )
        )
        return ExecutionResult(
            return_code=0,
            stdout="",
            stderr="",
            execution_time_sec=0.1,
            category=ResultCategory.EXPLOIT_CONFIRMED,
            invariant_violated=True,
            verification_result=vr,
            evidence=vr.evidence
        )

    monkeypatch.setattr(runner_mod, "run_payload_in_sandbox", mock_run_sandbox_different_inv)

    outcome_mismatch = verify_independent_replay_structured(
        target,
        payload,
        initial_evidence=init_evidence,
        expected_breached_invariants=["INV-VAULT-01-SOLVENCY"]
    )
    assert outcome_mismatch.is_confirmed is False
    assert outcome_mismatch.status == "INVARIANT_MISMATCH"

    # Mock 3: Replay fails (safe run or revert) -> FAILED
    def mock_run_sandbox_fail(t, p):
        return ExecutionResult(
            return_code=1,
            stdout="",
            stderr="EVM revert",
            execution_time_sec=0.1,
            category=ResultCategory.RUNTIME_REVERT,
            invariant_violated=False
        )

    monkeypatch.setattr(runner_mod, "run_payload_in_sandbox", mock_run_sandbox_fail)

    outcome_failed = verify_independent_replay_structured(
        target,
        payload,
        initial_evidence=init_evidence,
        expected_breached_invariants=["INV-VAULT-01-SOLVENCY"]
    )
    assert outcome_failed.is_confirmed is False
    assert outcome_failed.status == "FAILED"
