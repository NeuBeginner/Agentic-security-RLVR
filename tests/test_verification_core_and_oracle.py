"""
tests/test_verification_core_and_oracle.py

Verification Core and Trusted EVM State Oracle Test Suite.
Tests:
1. Trusted State Oracle evaluation and state hashing.
2. Protection against fake/spoofed log markers and unconfirmed snapshots.
3. Strict emitter address and cryptographic event topic verification.
4. Target-specific invariant registry precedence and rejection of Vault invariants for unknown targets.
5. Absence of synthetic state creation when snapshots are missing.
6. Secret stripping and environment sanitization.
7. Output log streaming and truncation to prevent log bombs.
8. Cheatcode detection and sandbox escape prevention.
9. Structured independent replay verification (confirmed, failed, mismatch, infra error).
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
    VerificationResult,
)
from core.evm_oracle import (
    TrustedEVMStateOracle,
    VaultSolvencyInvariant,
    ERC4626DilutionProtectionInvariant,
    ERC4626NonZeroSharesInvariant,
    compute_state_hash,
    trusted_oracle,
    CANONICAL_HARNESS_ADDRESS,
    TOPIC_SECURITY_INVARIANT_BREACHED,
    TOPIC_ORACLE_SNAPSHOT,
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


# =============================================================================
# HARDENING STAGE 1 AUDIT TESTS
# =============================================================================

def test_spoof_security_invariant_breached():
    """Spoofed SecurityInvariantBreached in logs without trusted harness event must be rejected."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id="c_spoof_event",
        return_code=0,
        test_status="Success",
        decoded_logs=["console.log('SecurityInvariantBreached(DEPOSITOR_SOLVENCY_COLLAPSE, 1000000)')"],
        stdout_text="SecurityInvariantBreached(DEPOSITOR_SOLVENCY_COLLAPSE)",
        stderr_text="",
        execution_time_sec=0.1,
        raw_logs=[]  # No genuine event logs from harness!
    )
    assert res.invariant_breach is False
    assert res.confidence_status == "REJECTED"
    assert "Spoofed" in (res.failure_reason or "")


def test_spoof_oracle_snapshot():
    """Spoofed [ORACLE_SNAPSHOT:...] in candidate stdout must be rejected and not create state."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    fake_snapshot = '[ORACLE_SNAPSHOT:{"final":{"vault_balance":0,"victim_owed_balance":100}}]'
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id="c_spoof_snap",
        return_code=0,
        test_status="Success",
        decoded_logs=[f"console.log('{fake_snapshot}')"],
        stdout_text=fake_snapshot,
        stderr_text="",
        execution_time_sec=0.1,
        raw_logs=[]  # No verified event from harness!
    )
    assert res.invariant_breach is False
    assert res.confidence_status == "REJECTED"
    assert res.evidence.state_delta["has_real_snapshot"] is False
    assert res.evidence.state_delta["final_state"] == {}


def test_wrong_emitter():
    """Event matching topic but emitted by untrusted exploit address must be rejected."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    exploit_address = "0x1111111111111111111111111111111111111111"
    wrong_emitter_logs = [
        {
            "address": exploit_address,
            "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
            "data": "0x00"
        }
    ]
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id="c_wrong_emit",
        return_code=0,
        test_status="Success",
        decoded_logs=["SecurityInvariantBreached"],
        stdout_text="",
        stderr_text="",
        execution_time_sec=0.1,
        raw_logs=wrong_emitter_logs,
        trusted_harness_address=CANONICAL_HARNESS_ADDRESS
    )
    assert res.invariant_breach is False
    assert res.confidence_status == "REJECTED"
    assert "Spoofed" in (res.failure_reason or "")


def test_unknown_target():
    """Unknown contract types must NOT have Vault invariants applied, returning rejection."""
    unknown_target = TargetProgram(name="UnknownCustomToken", source_code="contract UnknownCustomToken {}")
    invariants = trusted_oracle.get_invariants_for_target(unknown_target.name)
    assert invariants == []

    res = trusted_oracle.verify_execution(
        target=unknown_target,
        candidate_id="c_unknown",
        return_code=0,
        test_status="Success",
        decoded_logs=[],
        stdout_text="",
        stderr_text="",
        execution_time_sec=0.1
    )
    assert res.invariant_breach is False
    assert res.confidence_status == "REJECTED"
    assert "No applicable security invariants" in (res.failure_reason or "")


def test_absence_of_real_snapshot():
    """When real snapshot is absent, oracle must NOT fabricate synthetic state."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id="c_no_snap",
        return_code=0,
        test_status="Success",
        decoded_logs=[],
        stdout_text="Ran test cleanly",
        stderr_text="",
        execution_time_sec=0.1
    )
    assert res.confidence_status == "SAFE_RUN"
    assert res.evidence.state_delta["has_real_snapshot"] is False
    assert res.evidence.state_delta["initial_state"] == {}
    assert res.evidence.state_delta["final_state"] == {}
    assert "vault_balance" not in res.evidence.state_delta["initial_state"]


def test_generic_vs_specialized_invariants_precedence():
    """Specialized invariants must take strict precedence over generic Vault invariants."""
    erc4626_invs = trusted_oracle.get_invariants_for_target("ERC4626Vault")
    erc4626_ids = [inv.invariant_id for inv in erc4626_invs]
    assert "INV-ERC4626-01-NONZERO-SHARES" in erc4626_ids
    assert "INV-VAULT-01-SOLVENCY" not in erc4626_ids

    ac_invs = trusted_oracle.get_invariants_for_target("AccessControlVault")
    ac_ids = [inv.invariant_id for inv in ac_invs]
    assert "INV-ACCESS-01-UNAUTHORIZED-ADMIN" in ac_ids
    assert "INV-VAULT-01-SOLVENCY" not in ac_ids


# =============================================================================
# HARDENING STAGE 2 EXECUTION ISOLATION TESTS
# =============================================================================

def test_streaming_log_bomb_protection():
    """Streaming reader must terminate process before memory exhaustion when log quota exceeded."""
    from sandbox.runner import run_command_streaming_with_quota
    import sys
    
    # Spawn a python process that attempts to write 5MB to stdout
    cmd = [sys.executable, "-c", "import sys; sys.stdout.write('X' * (5 * 1024 * 1024)); sys.stdout.flush()"]
    ret, out, err, timed_out, quota_exceeded = run_command_streaming_with_quota(
        cmd=cmd,
        cwd=os.getcwd(),
        env=os.environ.copy(),
        timeout_sec=10.0,
        max_output_bytes=50 * 1024  # 50KB test limit
    )
    assert quota_exceeded is True
    assert len(out.encode("utf-8")) <= 60 * 1024
    assert "[LOG_QUOTA_EXCEEDED" in out


def test_process_tree_termination_on_timeout():
    """Process tree must be terminated upon timeout."""
    from sandbox.runner import run_command_streaming_with_quota
    import sys
    
    cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
    ret, out, err, timed_out, quota_exceeded = run_command_streaming_with_quota(
        cmd=cmd,
        cwd=os.getcwd(),
        env=os.environ.copy(),
        timeout_sec=0.3,
        max_output_bytes=1024 * 1024
    )
    assert timed_out is True


def test_prohibited_network_and_harness_inheritance_cheatcodes():
    """Exploits attempting network access or test harness inheritance must be blocked."""
    assert detect_prohibited_cheatcodes("vm.createFork('https://eth-mainnet')") is True
    assert detect_prohibited_cheatcodes("vm.rpcUrl('mainnet')") is True
    assert detect_prohibited_cheatcodes("contract Attacker is Test {}") is True
    assert detect_prohibited_cheatcodes("function testExploit() public {}") is True
    assert detect_prohibited_cheatcodes("vm.readFile('./secret.txt')") is True
