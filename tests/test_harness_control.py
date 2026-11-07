"""
tests/test_harness_control.py

Control tests for Foundry verification harness, contract validation,
and category-separated reward assignment (Round 2 & Round 3 requirements).
"""

import json
import pytest
from core.schemas import (
    TargetProgram,
    AttackHypothesis,
    ExploitPayload,
    ExecutionResult,
    VerificationVerdict,
    VerificationResult,
    ExecutionEvidence,
    InvariantResult,
    ResultCategory,
)
from core.config import config
from core.evaluator import evaluate_execution_trace
from core.llm_generator import validate_exploit_format, parse_model_response
from core.grpo_trainer import group_rollouts_by_prompt


VAULT_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be positive");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdrawAll() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
        totalDeposits -= balance;
    }
}
"""


def _typed_breach_evidence():
    evidence = ExecutionEvidence(
        candidate_id="candidate-typed",
        target_id="Vault",
        initial_state_hash="a" * 64,
        final_state_hash="b" * 64,
        execution_success=True,
    )
    invariant = InvariantResult(
        invariant_id="INV-VAULT-01-SOLVENCY",
        invariant_name="Depositor solvency",
        passed=False,
        observed_value={"deficit": 1},
        expected_condition="vault_balance >= liabilities",
    )
    return VerificationResult(
        execution_success=True,
        invariant_breach=True,
        confidence_status="PROVISIONAL_BREACH",
        evidence=evidence,
        invariant_results=[invariant],
        breached_invariants=["INV-VAULT-01-SOLVENCY"],
    )


def test_control_1_malformed_contract_name_triggers_format_error():
    """Confirms that an exploit naming contract differently is rejected before Foundry."""
    bad_solidity = """
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
```
"""
    target = TargetProgram(name="Vault", source_code=VAULT_SOL)
    payload = parse_model_response(target, bad_solidity)

    assert not payload.format_valid
    assert "instead of mandatory 'ExploitModule'" in payload.format_error_reason

    # Evaluator must assign GENERATION_FORMAT_ERROR and reward -0.50
    dummy_result = ExecutionResult(
        return_code=-4,
        stdout="",
        stderr="",
        execution_time_sec=0.0,
        category=ResultCategory.GENERATION_FORMAT_ERROR
    )
    verdict = evaluate_execution_trace(payload, dummy_result)

    assert verdict.category == ResultCategory.GENERATION_FORMAT_ERROR
    assert verdict.reward_score == config.REWARD_FORMAT_ERROR
    assert not verdict.is_verified


def test_control_2_missing_methods_triggers_format_error():
    """Confirms that missing constructor or runExploit inside ExploitModule is rejected."""
    missing_entrypoint = """
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitModule {
    constructor(address _target) payable {}
    // Missing function runExploit()
}
```
"""
    target = TargetProgram(name="Vault", source_code=VAULT_SOL)
    payload = parse_model_response(target, missing_entrypoint)

    assert not payload.format_valid
    assert "missing mandatory entrypoint" in payload.format_error_reason.lower()


def test_control_3_benign_exploit_does_not_receive_positive_reward():
    """
    Confirms that a benign exploit that compiles cleanly but reverts in harness
    receives RUNTIME_REVERT (reward -0.25) and NOT a positive reward.
    """
    valid_solidity = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Vault} from "../src/Vault.sol";

contract ExploitModule {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {}
}
"""
    is_valid, _ = validate_exploit_format(valid_solidity)
    assert is_valid

    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Test trace",
            attack_vector="Test vector"
        ),
        test_code=valid_solidity,
        format_valid=True
    )

    # Simulate Foundry harness failing invariant check (clean revert)
    result = ExecutionResult(
        return_code=1,
        stdout="",
        stderr="",
        execution_time_sec=1.2,
        category=ResultCategory.RUNTIME_REVERT,
        revert_reason="EXPLOIT_FAILED: Vault remains solvent, victim funds are secure",
        test_status="Failure",
        invariant_violated=False
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.RUNTIME_REVERT
    assert verdict.reward_score == config.REWARD_RUNTIME_REVERT
    assert verdict.reward_score < 0.0
    assert not verdict.is_verified


def test_control_4a_unreplayed_breach_receives_partial_reward_only():
    """
    Round 3: Confirms that an invariant breach WITHOUT independent replay
    gets INVARIANT_BREACH_UNREPLAYED, reward +0.50, and is_verified=False.
    """
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Test trace",
            attack_vector="Test vector"
        ),
        test_code="contract ExploitModule { ... }",
        format_valid=True
    )

    result = ExecutionResult(
        return_code=0,
        stdout="",
        stderr="",
        execution_time_sec=2.1,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        invariant_violated=True,
        reproducibility_confirmed=False,  # NOT confirmed in replay!
        verification_result=_typed_breach_evidence(),
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert verdict.reward_score == config.REWARD_BREACH_NO_REPLAY
    assert verdict.reward_score == 0.50
    assert not verdict.is_verified  # Must NOT be marked verified without replay!
    assert not verdict.reproducible


def test_control_4b_replayed_breach_receives_confirmed_exploit():
    """
    Round 3: Confirms that an invariant breach WITH independent replay
    gets EXPLOIT_CONFIRMED, full reward +1.0, and is_verified=True.
    """
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Test trace",
            attack_vector="Test vector"
        ),
        test_code="contract ExploitModule { ... }",
        format_valid=True
    )

    result = ExecutionResult(
        return_code=0,
        stdout="",
        stderr="",
        execution_time_sec=2.1,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        invariant_violated=True,
        reproducibility_confirmed=True,  # Confirmed!
        verification_result=_typed_breach_evidence(),
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.EXPLOIT_CONFIRMED
    assert verdict.reward_score == config.REWARD_INVARIANT_BREACH
    assert verdict.reward_score == 1.00
    assert verdict.is_verified
    assert verdict.reproducible




def test_control_fake_marker_cannot_award_positive_reward_without_typed_evidence():
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Test trace",
            attack_vector="Test vector",
        ),
        test_code="contract ExploitModule { ... }",
    )
    result = ExecutionResult(
        return_code=0,
        stdout="[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]",
        stderr="",
        execution_time_sec=0.1,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        decoded_logs=['SecurityInvariantBreached("DEPOSITOR_SOLVENCY_COLLAPSE", 1)'],
        invariant_violated=True,
        reproducibility_confirmed=True,
    )

    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.INFRA_ERROR
    assert verdict.reward_score == config.REWARD_INFRA_ERROR
    assert verdict.is_verified is False


def test_control_5_infra_error_does_not_penalize_model():
    """
    Confirms that an environment or harness infrastructure failure
    assigns INFRA_ERROR and neutral reward 0.0 (zero penalty).
    """
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Test trace",
            attack_vector="Test vector"
        ),
        test_code="contract ExploitModule { ... }",
        format_valid=True
    )

    result = ExecutionResult(
        return_code=-5,
        stdout="",
        stderr="INFRA_ERROR: Foundry executable not found or disk full",
        execution_time_sec=0.1,
        category=ResultCategory.INFRA_ERROR,
        invariant_violated=False
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.INFRA_ERROR
    assert verdict.reward_score == config.REWARD_INFRA_ERROR
    assert verdict.reward_score == 0.0
    assert not verdict.is_verified


def test_control_6_cheatcode_detection_penalizes_severely():
    """Confirms that cheatcode tampering is detected and penalized with -1.0."""
    cheatcode_solidity = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";

contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {
        vm.deal(address(this), 1000 ether);
    }
}
"""
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Test trace",
            attack_vector="Test vector"
        ),
        test_code=cheatcode_solidity,
        format_valid=True
    )

    result = ExecutionResult(
        return_code=-3,
        stdout="",
        stderr="Security Violation",
        execution_time_sec=0.01,
        category=ResultCategory.CHEATCODE_DETECTED,
        cheatcode_detected=True,
        invariant_violated=False
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.CHEATCODE_DETECTED
    assert verdict.reward_score == -1.0
    assert not verdict.is_verified


def test_control_7_nested_contract_scoping_check():
    """
    Round 3: Verifies that if runExploit is declared in another contract
    while ExploitModule lacks it, the balanced-brace parser catches it!
    """
    tricky_solidity = """
contract HelperContract {
    function runExploit() external payable {}
}

contract ExploitModule {
    constructor(address _target) payable {}
    // ExploitModule itself lacks runExploit()
}
"""
    is_valid, reason = validate_exploit_format(tricky_solidity)
    assert not is_valid
    assert "missing mandatory entrypoint" in reason.lower()


def test_control_8_grpo_strictly_excludes_infra_error():
    """
    Round 3: Confirms that group_rollouts_by_prompt strictly excludes
    INFRA_ERROR trajectories from GRPO groups and advantage calculation.
    """
    prompt = "Test prompt for Vault"
    dataset = [
        {"target_name": "Vault", "prompt_used": prompt, "reward": -0.5, "category": "COMPILATION_ERROR"},
        {"target_name": "Vault", "prompt_used": prompt, "reward": 0.0, "category": "INFRA_ERROR"}, # MUST BE FILTERED
        {"target_name": "Vault", "prompt_used": prompt, "reward": -0.25, "category": "RUNTIME_REVERT"},
        {"target_name": "Vault", "prompt_used": prompt, "reward": 1.0, "category": "EXPLOIT_CONFIRMED"},
    ]

    groups = group_rollouts_by_prompt(dataset, group_size=4)
    assert len(groups) == 1
    g = groups[0]

    # Verify INFRA_ERROR was excluded
    categories_in_group = [r.category for r in g.rollouts]
    assert "INFRA_ERROR" not in categories_in_group
    assert len(g.rollouts) == 3

    # Mean reward must be mean(-0.5, -0.25, 1.0) = 0.0833, NOT affected by 0.0 from INFRA_ERROR!
    expected_mean = (-0.5 + -0.25 + 1.0) / 3
    assert abs(g.mean_reward - expected_mean) < 1e-4
