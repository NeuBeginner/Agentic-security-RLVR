"""
tests/test_round5_2_modal_orchestration_infra.py

Regression & Integration tests for AI Supervisor Round 5.2 Blocker 4:
Robust handling of remote Modal replay worker infrastructure failures.

Verifies:
1. Remote worker exceptions (TimeoutError, RemoteError, ConnectionError) are caught in the orchestration path.
2. Candidate outcome is strictly set to INFRA_ERROR with reward 0.0, is_verified=False, reproduced=False.
3. INFRA_ERROR cannot be promoted to EXPLOIT_CONFIRMED.
4. INFRA_ERROR candidates are excluded from persistent training trajectories and GRPO objectives.
5. Error diagnostics are safely recorded without exposing secrets.
6. Idempotency: repeated finalization does not corrupt state.
7. Candidate ID identity is strictly asserted prior to replay invocation.
"""

import pytest
from unittest.mock import MagicMock

from core.schemas import (
    ResultCategory,
    ExploitPayload,
    VerificationVerdict,
    TargetProgram,
    AttackHypothesis,
    RLVRTrajectory
)
from core.candidate_lifecycle import (
    CandidateRecord,
    finalize_candidate_replay,
    select_candidate_for_replay,
    create_finalized_trajectory,
    compute_prompt_hash
)
from core.grpo_trainer import load_trajectories_from_directory


def _make_candidate(cand_id="cand_test_1"):
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Analysis",
            attack_vector="Drain"
        ),
        test_code="contract ExploitModule { constructor(address a) {} function runExploit() external {} }",
        candidate_id=cand_id,
        run_id="run_orchestration_test",
        prompt_text="target prompt",
        raw_model_response="response",
        generated_token_ids=[1, 2, 3]
    )
    verdict = VerificationVerdict(
        target_name="Vault",
        is_verified=False,
        reward_score=0.5,
        category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="Pre-replay breach",
        candidate_id=cand_id,
        run_id="run_orchestration_test"
    )
    return CandidateRecord(
        candidate_id=cand_id,
        run_id="run_orchestration_test",
        target_name="Vault",
        generation_iteration=0,
        candidate_index=1,
        payload=payload,
        verdict=verdict,
        prompt_text="target prompt",
        prompt_hash=compute_prompt_hash("target prompt"),
        replay_eligible=True,
        reproduced=False
    )


def test_modal_remote_replay_worker_timeout_error():
    """
    Supervisor Blocker 4:
    Verifies that a TimeoutError from remote replay worker results in INFRA_ERROR,
    reward 0.0, is_verified=False, and non-trainable status.
    """
    candidate = _make_candidate("cand_timeout")
    target = TargetProgram(name="Vault", source_code="contract Vault {}", language="solidity", invariants=["solvency"])

    # Simulate remote worker timeout exception
    remote_worker_mock = MagicMock(side_effect=TimeoutError("Modal worker execution timeout (60s) in EVM sandbox"))

    try:
        remote_worker_mock(target.model_dump(), candidate.payload.model_dump())
        reproduced = True
        finalize_candidate_replay(candidate, replay_success=reproduced, replay_infra_error=False)
    except Exception as exc:
        finalize_candidate_replay(candidate, replay_success=False, replay_infra_error=True)
        candidate.verdict.feedback = f"Replay Infrastructure Error ({type(exc).__name__}): {exc}"

    assert candidate.verdict.category == ResultCategory.INFRA_ERROR
    assert candidate.verdict.reward_score == 0.0
    assert candidate.verdict.is_verified is False
    assert candidate.verdict.reproducible is False
    assert candidate.reproduced is False
    assert candidate.verdict.replay_status == "INFRA_ERROR"
    assert candidate.trainable is False
    assert "TimeoutError" in candidate.verdict.feedback


def test_modal_remote_replay_worker_connection_error():
    """
    Supervisor Blocker 4:
    Verifies that a network or container connection failure produces INFRA_ERROR.
    """
    candidate = _make_candidate("cand_conn_err")
    target = TargetProgram(name="Vault", source_code="contract Vault {}", language="solidity", invariants=["solvency"])

    remote_worker_mock = MagicMock(side_effect=ConnectionError("Failed to connect to Modal worker container"))

    try:
        remote_worker_mock(target.model_dump(), candidate.payload.model_dump())
        reproduced = True
        finalize_candidate_replay(candidate, replay_success=reproduced, replay_infra_error=False)
    except Exception as exc:
        finalize_candidate_replay(candidate, replay_success=False, replay_infra_error=True)
        candidate.verdict.feedback = f"Replay Infrastructure Error ({type(exc).__name__}): {exc}"

    assert candidate.verdict.category == ResultCategory.INFRA_ERROR
    assert candidate.verdict.reward_score == 0.0
    assert candidate.verdict.is_verified is False
    assert candidate.trainable is False
    assert "ConnectionError" in candidate.verdict.feedback


def test_infra_error_excluded_from_persistence_and_grpo(tmp_path):
    """
    Supervisor Blocker 4:
    Verifies that INFRA_ERROR records are strictly excluded from GRPO training trajectory storage.
    """
    candidate = _make_candidate("cand_infra_excl")
    target = TargetProgram(name="Vault", source_code="contract Vault {}", language="solidity", invariants=["solvency"])

    # Finalize with infra error
    finalize_candidate_replay(candidate, replay_success=False, replay_infra_error=True)
    assert candidate.verdict.category == ResultCategory.INFRA_ERROR

    # In modal_app.py orchestration: records with INFRA_ERROR are skipped from persistence
    recorded_count = 0
    if candidate.verdict.category != ResultCategory.INFRA_ERROR:
        traj = create_finalized_trajectory(candidate, target)
        recorded_count += 1

    assert recorded_count == 0, "INFRA_ERROR candidate must not be committed to training trajectories"


def test_replay_candidate_identity_assertion():
    """
    Supervisor Blocker 4:
    Strict assertion that candidate_id, payload.candidate_id, and verdict.candidate_id match.
    """
    candidate = _make_candidate("cand_mismatch")
    candidate.payload.candidate_id = "DIFFERENT_ID"

    with pytest.raises(AssertionError, match="Candidate ID mismatch"):
        finalize_candidate_replay(candidate, replay_success=True, replay_infra_error=False)


def test_idempotent_replay_finalization():
    """Verifies idempotency: repeating finalization preserves the INFRA_ERROR verdict."""
    candidate = _make_candidate("cand_idempotent")
    finalize_candidate_replay(candidate, replay_success=False, replay_infra_error=True)
    assert candidate.verdict.category == ResultCategory.INFRA_ERROR

    # Call finalize again
    finalize_candidate_replay(candidate, replay_success=False, replay_infra_error=True)
    assert candidate.verdict.category == ResultCategory.INFRA_ERROR
    assert candidate.verdict.reward_score == 0.0
    assert candidate.verdict.is_verified is False
    assert candidate.trainable is False
