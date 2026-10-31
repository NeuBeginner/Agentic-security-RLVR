"""
tests/test_evaluator_semantics.py

Regression test suite for Section 5 (Round 4):
Strict Evaluator and Reward Semantics for all Result Categories.
"""

import pytest
from core.schemas import (
    ResultCategory,
    ExploitPayload,
    ExecutionResult,
    VerificationVerdict,
    AttackHypothesis
)
from core.evaluator import evaluate_execution_trace
from core.candidate_lifecycle import finalize_candidate_replay, CandidateRecord
from core.config import config


def make_payload() -> ExploitPayload:
    return ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Testing semantics",
            attack_vector="receive()"
        ),
        test_code="contract ExploitModule { constructor(address a) payable {} function runExploit() external payable {} }"
    )


def test_evaluator_confirmed_exploit_semantics():
    """Test 1: Confirmed exploit requires reproducibility confirmation, receives +1.00 and is_verified=True."""
    payload = make_payload()
    result = ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit()",
        stderr="",
        execution_time_sec=0.4,
        invariant_violated=True,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        reproducibility_confirmed=True
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.EXPLOIT_CONFIRMED
    assert verdict.reward_score == config.REWARD_INVARIANT_BREACH  # +1.00
    assert verdict.is_verified is True
    assert verdict.reproducible is True


def test_evaluator_unreplayed_breach_semantics():
    """Test 2: Breach without independent replay receives +0.50 and is_verified=False."""
    payload = make_payload()
    result = ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit()",
        stderr="",
        execution_time_sec=0.4,
        invariant_violated=True,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        reproducibility_confirmed=False
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert verdict.reward_score == config.REWARD_BREACH_NO_REPLAY  # +0.50
    assert verdict.is_verified is False
    assert verdict.reproducible is False


def test_evaluator_replay_infrastructure_failure_semantics():
    """Test 3: Infrastructure failure during replay receives 0.00, is_verified=False, and is marked INFRA_ERROR."""
    payload = make_payload()
    payload.candidate_id = "cand_infra"
    cand = CandidateRecord(
        candidate_id="cand_infra",
        run_id="run-infra",
        target_name="Vault",
        payload=payload,
        verdict=VerificationVerdict(
            target_name="Vault",
            is_verified=False,
            reward_score=0.50,
            category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            vulnerability_type="ReentrancyDrain",
            poc_code=payload.test_code,
            feedback="Initial run breached",
            candidate_id="cand_infra"
        )
    )

    finalized = finalize_candidate_replay(cand, replay_success=False, replay_infra_error=True)

    assert finalized.verdict.category == ResultCategory.INFRA_ERROR
    assert finalized.verdict.reward_score == config.REWARD_INFRA_ERROR  # 0.00
    assert finalized.verdict.is_verified is False
    assert finalized.verdict.reproducible is False
    assert finalized.verdict.replay_status == "INFRA_ERROR"


def test_evaluator_compilation_failure_semantics():
    """Test 4: Compilation error receives -0.50, is_verified=False, and category COMPILATION_ERROR."""
    payload = make_payload()
    result = ExecutionResult(
        return_code=1,
        stdout="Error (7576): Undeclared identifier 'foo'",
        stderr="",
        execution_time_sec=0.2,
        invariant_violated=False,
        category=ResultCategory.COMPILATION_ERROR
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.COMPILATION_ERROR
    assert verdict.reward_score == config.REWARD_COMPILATION_FAIL  # -0.50
    assert verdict.is_verified is False
    assert verdict.reproducible is False


def test_evaluator_runtime_revert_semantics():
    """Test 5: Runtime revert receives -0.25, is_verified=False, and category RUNTIME_REVERT."""
    payload = make_payload()
    result = ExecutionResult(
        return_code=1,
        stdout="[FAIL: revert: EXPLOIT_FAILED] testExploit()",
        stderr="",
        execution_time_sec=0.3,
        invariant_violated=False,
        revert_reason="EXPLOIT_FAILED",
        category=ResultCategory.RUNTIME_REVERT
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.RUNTIME_REVERT
    assert verdict.reward_score == config.REWARD_RUNTIME_REVERT  # -0.25
    assert verdict.is_verified is False
    assert verdict.reproducible is False


def test_evaluator_safe_run_semantics():
    """Test 6: Safe run (test passed, but invariant unbroken) receives -0.10, is_verified=False."""
    payload = make_payload()
    result = ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit()",
        stderr="",
        execution_time_sec=0.3,
        invariant_violated=False,  # Invariant intact!
        test_status="Success",
        category=ResultCategory.SAFE_RUN
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.SAFE_RUN
    assert verdict.reward_score == config.REWARD_SAFE_RUN  # -0.10
    assert verdict.is_verified is False


def test_evaluator_cheatcode_semantics():
    """Test 7: Forbidden cheatcode usage receives -1.00, is_verified=False."""
    payload = make_payload()
    result = ExecutionResult(
        return_code=1,
        stdout="Prohibited cheatcode detected: vm.prank",
        stderr="",
        execution_time_sec=0.1,
        cheatcode_detected=True,
        category=ResultCategory.CHEATCODE_DETECTED
    )
    verdict = evaluate_execution_trace(payload, result)

    assert verdict.category == ResultCategory.CHEATCODE_DETECTED
    assert verdict.reward_score == config.REWARD_CHEATCODE_PENALTY  # -1.00
    assert verdict.is_verified is False
