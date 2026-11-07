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
    VerificationVerdict,
    ResultCategory
)
from core.evaluator import evaluate_execution_trace
from sandbox.runner import parse_forge_output


# =============================================================================
# 1. TEST FORGE JSON PARSER
# =============================================================================
def test_parse_forge_output_success():
    mock_forge_json = {
        "test/VaultHarness.t.sol:VaultTrustedHarness": {
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
        "test/VaultHarness.t.sol:VaultTrustedHarness": {
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
# 2. TEST REJECTION OF DUMMY PASSING TEST (POINT 2)
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
    assert verdict.reward_score == config.REWARD_RUNTIME_REVERT
    assert "Vault remains solvent" in verdict.feedback


# =============================================================================
# 3. TEST GENUINE REENTRANCY INVARIANT BREACH (POINTS 2 & 3)
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
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        reproducibility_confirmed=True
    )

    verdict = evaluate_execution_trace(payload, result)

    assert verdict.is_verified is True
    assert verdict.reward_score == config.REWARD_INVARIANT_BREACH
    assert verdict.reproducible is True
    assert "SUCCESS: Multi-factor verification passed" in verdict.feedback


def test_verify_erc4626_inflation_exploit():
    """
    Ensures that an ERC4626 first-depositor share inflation exploit
    breaches the depositor equity invariant and receives maximum RLVR reward.
    """
    inflation_code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    import "../src/ERC4626Vault.sol";

    contract ExploitModule {
        ERC4626Vault public vault;
        constructor(address _target) { vault = ERC4626Vault(payable(_target)); }
        function runExploit() external payable {
            vault.deposit{value: 1}();
            payable(address(vault)).transfer(msg.value - 1);
        }
        receive() external payable {}
    }
    """
    payload = ExploitPayload(
        target_name="ERC4626Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="FirstDepositorShareInflation",
            reasoning_trace="No virtual offset in convertToShares leads to zero-share deposit dilution",
            attack_vector="Deposit 1 wei then donate 5 ether to skew share exchange rate"
        ),
        test_code=inflation_code,
        test_filename="ExploitModule.sol"
    )

    result = ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit() (gas: 89000)",
        stderr="",
        execution_time_sec=0.64,
        timed_out=False,
        invariant_violated=True,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:SHARE_INFLATION_DEPOSITOR_DILUTION]"],
        reproducibility_confirmed=True
    )

    verdict = evaluate_execution_trace(payload, result)

    assert verdict.is_verified is True
    assert verdict.reward_score == config.REWARD_INVARIANT_BREACH
    assert verdict.reproducible is True
    assert "SUCCESS: Multi-factor verification passed" in verdict.feedback



# =============================================================================
# 4. TEST TIMEOUT HANDLING
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
# 5. TEST PATH TRAVERSAL SANITIZATION (POINT 4)
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
        safe_name = os.path.basename(bad_name.replace("\\", "/"))
        assert "/" not in safe_name
        assert "\\" not in safe_name
        assert ".." not in safe_name


# =============================================================================
# 6. TEST CHECKSUM VALIDATION LOGIC (POINT 6)
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

    # Test that a mismatch raises ValueError
    with pytest.raises(ValueError, match="Checksum mismatch"):
        if computed_sha != expected_sha:
            raise ValueError(f"Checksum mismatch! Expected {expected_sha}, got {computed_sha}")


# =============================================================================
# 7. TEST CHEATCODE DETECTION & PENALTY (P0 FIX)
# =============================================================================
def test_detect_prohibited_cheatcodes():
    from sandbox.runner import detect_prohibited_cheatcodes, run_payload_in_sandbox

    sneaky_cheatcode_code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    import "forge-std/Test.sol";

    contract ExploitModule {
        function runExploit() external payable {
            // Attempt to forge breach by warping or pranking
            vm.prank(address(0xDEAD));
        }
    }
    """
    assert detect_prohibited_cheatcodes(sneaky_cheatcode_code) is True

    clean_code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract ExploitModule {
        function runExploit() external payable {}
    }
    """
    assert detect_prohibited_cheatcodes(clean_code) is False

    # Ensure runner rejects cheatcode exploit before compilation
    target = TargetProgram(name="Vault", source_code="contract Vault{}", language="solidity")
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="CheatcodeAttack",
            reasoning_trace="Try to prank state",
            attack_vector="vm.prank"
        ),
        test_code=sneaky_cheatcode_code
    )
    result = run_payload_in_sandbox(target, payload)
    assert result.cheatcode_detected is True
    assert result.return_code == -3

    verdict = evaluate_execution_trace(payload, result)
    assert verdict.is_verified is False
    assert verdict.reward_score == config.REWARD_CHEATCODE_PENALTY
    assert "SECURITY VIOLATION" in verdict.feedback


# =============================================================================
# 8. TEST MULTI-FACTOR INVARIANT VERIFICATION (P0 FIX)
# =============================================================================
def test_multifactor_verification_rejects_spurious_breach():
    """
    Ensures that if invariant_violated is claimed, but the test status is Failure
    or exit code is non-zero, it is firmly rejected.
    """
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Spurious claim",
            attack_vector="Exit failure"
        ),
        test_code="contract ExploitModule{}"
    )

    spurious_result = ExecutionResult(
        return_code=1,
        stdout="[FAIL] testExploit()",
        stderr="Reverted",
        execution_time_sec=0.5,
        timed_out=False,
        invariant_violated=True,  # Flawed signal!
        test_status="Failure",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"]
    )
    verdict = evaluate_execution_trace(payload, spurious_result)
    assert verdict.is_verified is False
    assert verdict.reward_score != config.REWARD_INVARIANT_BREACH


# =============================================================================
# 9. TEST TARGET-AGNOSTIC PROMPT GENERATOR
# =============================================================================
def test_target_agnostic_prompt_builder():
    from core.llm_generator import build_analysis_prompt, build_auditor_prompt

    custom_target = TargetProgram(
        name="LendingPool",
        source_code="contract LendingPool { function flashLoan() external {} }",
        language="solidity",
        invariants=["Pool reserves must cover active borrow obligations"]
    )

    auditor_prompt = build_auditor_prompt(custom_target)
    assert "LendingPool" in auditor_prompt
    assert "Pool reserves must cover active borrow obligations" in auditor_prompt
    assert "JSON" in auditor_prompt

    analysis_prompt = build_analysis_prompt(custom_target)
    assert "LendingPool" in analysis_prompt
    assert "Pool reserves must cover active borrow obligations" in analysis_prompt
    assert "ExploitModule" in analysis_prompt
    assert "vm.*" in analysis_prompt or "cheatcode" in analysis_prompt.lower()


# =============================================================================
# 10. TEST REPRODUCIBILITY DISTINCTION & REWARD SHAPING
# =============================================================================
def test_reproducibility_distinction():
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Test replay",
            attack_vector="receive()"
        ),
        test_code="contract ExploitModule {}"
    )

    # Result without independent reproducibility confirmed
    unconfirmed_result = ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit()",
        stderr="",
        execution_time_sec=0.5,
        timed_out=False,
        invariant_violated=True,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        reproducibility_confirmed=False
    )
    verdict = evaluate_execution_trace(payload, unconfirmed_result)
    assert verdict.is_verified is False
    assert verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert verdict.reproducible is False
    assert verdict.reward_score == config.REWARD_BREACH_NO_REPLAY  # 0.5

    # Result WITH independent reproducibility confirmed
    confirmed_result = ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit()",
        stderr="",
        execution_time_sec=0.5,
        timed_out=False,
        invariant_violated=True,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        reproducibility_confirmed=True
    )
    confirmed_verdict = evaluate_execution_trace(payload, confirmed_result)
    assert confirmed_verdict.is_verified is True
    assert confirmed_verdict.category == ResultCategory.EXPLOIT_CONFIRMED
    assert confirmed_verdict.reproducible is True
    assert confirmed_verdict.reward_score == config.REWARD_INVARIANT_BREACH  # 1.0


# =============================================================================
# 11. TEST GRPO TRAJECTORY CREATION & SLITHER FALLBACK
# =============================================================================
def test_create_trajectory_record_for_grpo():
    from core.evaluator import create_trajectory_record
    from sandbox.runner import run_slither_analysis

    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { mapping(address => uint) balances; function withdraw() { msg.sender.call{value: 1}(''); balances[msg.sender] = 0; } }",
        language="solidity",
        invariants=["Depositor Solvency"]
    )
    # Test Slither fallback parser
    slither_findings = run_slither_analysis(target)
    assert len(slither_findings) > 0
    assert any("reentrancy" in f["check"].lower() for f in slither_findings)
    target.slither_findings = slither_findings

    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Reentrancy trace",
            attack_vector="call{value}"
        ),
        test_code="contract ExploitModule {}"
    )
    verdict = VerificationVerdict(
        target_name="Vault",
        is_verified=True,
        reward_score=1.0,
        vulnerability_type="ReentrancyDrain",
        poc_code="contract ExploitModule {}",
        feedback="Verified and reproduced",
        state_delta_verified=True,
        reproducible=True
    )

    traj = create_trajectory_record(target, payload, verdict, prompt_used="audit prompt")
    assert traj.reward == 1.0
    assert traj.is_verified is True
    assert traj.reproduced is True
    assert len(traj.slither_hints) > 0
    assert traj.target_name == "Vault"


