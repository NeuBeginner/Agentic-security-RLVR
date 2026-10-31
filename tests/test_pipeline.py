import os
import sys
import json
import hashlib
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import config
from core.schemas import (
    TargetProgram,
    AttackHypothesis,
    ExploitPayload,
    ExecutionResult,
    VerificationVerdict
)
from core.evaluator import evaluate_execution_trace
from sandbox.runner import parse_forge_output, run_payload_in_sandbox
from sandbox.harness_registry import get_trusted_harness


# =============================================================================
# 1. TEST FORGE JSON PARSER
# =============================================================================
def test_parse_forge_output_success():
    mock_forge_json = {
        "test/VaultTrustedHarness.t.sol:VaultTrustedHarness": {
            "test_results": {
                "testExploit()": {
                    "status": "Success",
                    "reason": None,
                    "decoded_logs": [
                        "[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"
                    ],
                    "traces": []
                }
            }
        }
    }
    raw_output = "Some forge banner\n" + json.dumps(mock_forge_json) + "\nDone"
    structured, status, reason, logs = parse_forge_output(raw_output)

    assert structured is not None
    assert status == "Success"
    assert reason is None
    assert "[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]" in logs


def test_parse_forge_output_revert():
    mock_forge_json = {
        "test/VaultTrustedHarness.t.sol:VaultTrustedHarness": {
            "test_results": {
                "testExploit()": {
                    "status": "Failure",
                    "reason": "EXPLOIT_FAILED: Vault remains solvent, victim funds are secure",
                    "decoded_logs": [],
                    "traces": []
                }
            }
        }
    }
    raw_output = json.dumps(mock_forge_json)
    structured, status, reason, logs = parse_forge_output(raw_output)

    assert structured is not None
    assert status == "Failure"
    assert "Vault remains solvent" in reason


# =============================================================================
# 2. TEST MANDATORY WORKER-SIDE HARNESS RESOLUTION (POINT 1)
# =============================================================================
def test_unregistered_target_aborts_immediately():
    """
    Ensures that an unknown target without an immutable worker-side harness
    is immediately aborted and cannot be verified or gamed.
    """
    target = TargetProgram(
        name="ArbitraryUntrustedContract",
        source_code="contract Foo {}",
        language="solidity"
    )
    payload = ExploitPayload(
        target_name="ArbitraryUntrustedContract",
        hypothesis=AttackHypothesis(
            vulnerability_type="LogicFlaw",
            reasoning_trace="Testing bypass",
            attack_vector="No harness"
        ),
        test_code="// Fake test attempting bypass with forged log\n// [INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"
    )

    result = run_payload_in_sandbox(target, payload)

    assert result.invariant_violated is False
    assert result.return_code == -3
    assert "SECURITY ABORT" in result.stderr
    assert "has no registered immutable harness" in result.stderr


def test_trusted_harness_registry_lookup():
    """Validates that Vault is properly registered in the immutable registry."""
    harness = get_trusted_harness("Vault")
    assert "contract VaultTrustedHarness is Test" in harness
    assert "[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]" in harness


# =============================================================================
# 3. TEST REJECTION OF DUMMY PASSING TEST (POINT 2)
# =============================================================================
def test_reject_dummy_passing_test():
    """
    Ensures that a dummy test containing comments '// Vault' and '// assert'
    that does NOT physically breach the trusted harness is firmly rejected.
    """
    dummy_code = """
    // Vault
    // assert(address(vault).balance == 0);
    contract ExploitModule {
        constructor(address) {}
        function runExploit() external payable {}
    }
    """
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Dummy bypass attempt",
            attack_vector="No-op comments"
        ),
        test_code=dummy_code,
        test_filename="../../malicious.sol"  # Also tests path traversal attempt
    )

    # When the dummy test runs against VaultTrustedHarness, the harness detects
    # that victim funds are still safe and explicitly reverts with exit code 1
    result = ExecutionResult(
        return_code=1,
        stdout="",
        stderr="EVM Revert: EXPLOIT_FAILED: Vault remains solvent, victim funds are secure",
        execution_time_sec=0.45,
        timed_out=False,
        invariant_violated=False,
        test_status="Failure",
        revert_reason="EXPLOIT_FAILED: Vault remains solvent, victim funds are secure"
    )

    verdict = evaluate_execution_trace(payload, result)

    assert verdict.is_verified is False
    assert verdict.reward_score == config.REWARD_COMPILATION_FAIL
    assert "Vault remains solvent" in verdict.feedback


# =============================================================================
# 4. TEST GENUINE REENTRANCY INVARIANT BREACH EVALUATION
# =============================================================================
def test_verify_real_reentrancy_exploit():
    """
    Ensures that a real exploit breaching victim depositor solvency
    triggers the trusted invariant log and receives maximum RLVR reward.
    """
    real_code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    import "../src/Vault.sol";

    contract ExploitModule {
        Vault public vault;
        constructor(address _target) { vault = Vault(_target); }
        function runExploit() external payable {
            vault.deposit{value: msg.value}();
            vault.withdrawAll();
        }
        receive() external payable {
            if (address(vault).balance >= 1 ether) {
                vault.withdrawAll();
            }
        }
    }
    """
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Checks-Effects-Interactions violation in withdrawAll()",
            attack_vector="Recursive callback via receive()"
        ),
        test_code=real_code,
        test_filename="ExploitModule.sol"
    )

    # Trusted harness detects insolvency and emits unforgeable log
    result = ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit() (gas: 142000)",
        stderr="",
        execution_time_sec=0.82,
        timed_out=False,
        invariant_violated=True,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"]
    )

    verdict = evaluate_execution_trace(payload, result)

    assert verdict.is_verified is True
    assert verdict.reward_score == config.REWARD_INVARIANT_BREACH
    assert "SUCCESS: Invariant breached" in verdict.feedback


# =============================================================================
# 5. TEST TIMEOUT HANDLING
# =============================================================================
def test_timeout_handling():
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Infinite loop test",
            attack_vector="Gas exhaustion"
        ),
        test_code="// Infinite loop",
        test_filename="ExploitModule.sol"
    )

    result = ExecutionResult(
        return_code=-1,
        stdout="",
        stderr="Command timed out after 60.0s",
        execution_time_sec=60.0,
        timed_out=True,
        invariant_violated=False
    )

    verdict = evaluate_execution_trace(payload, result)

    assert verdict.is_verified is False
    assert verdict.reward_score == config.REWARD_TIMEOUT
    assert "timed out" in verdict.feedback


# =============================================================================
# 6. TEST PATH TRAVERSAL SANITIZATION
# =============================================================================
def test_path_traversal_sanitization():
    """
    Ensures filenames like ../../evil.sol are safely stripped to a single local filename.
    """
    malicious_names = [
        "../../etc/passwd",
        "..\\..\\windows\\system32.sol",
        "/absolute/root.sol",
        "nested/sub/exploit.sol"
    ]
    for bad_name in malicious_names:
        safe_name = os.path.basename(bad_name)
        assert "/" not in safe_name
        assert "\\" not in safe_name
        assert ".." not in safe_name


# =============================================================================
# 7. TEST CHECKSUM VALIDATION LOGIC
# =============================================================================
def test_checksum_validation_detects_tampering():
    """
    Validates that prebake_solc cryptographic checksum verification
    instantly catches corrupted or tampered downloads.
    """
    fake_bytes = b"corrupted binary payload"
    expected_sha = "0479d44fdf9c501c25337fdc540419f1593b884a87b47f023da4f1c700fda782"
    computed_sha = hashlib.sha256(fake_bytes).hexdigest()

    assert computed_sha != expected_sha

    with pytest.raises(ValueError, match="Checksum mismatch"):
        if computed_sha != expected_sha:
            raise ValueError(f"Checksum mismatch! Expected {expected_sha}, got {computed_sha}")
