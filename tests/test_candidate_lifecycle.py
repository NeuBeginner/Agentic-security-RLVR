"""
tests/test_candidate_lifecycle.py

Regression test suite for Section 1 (Round 4):
Candidate Lifecycle, Ranking Policy, and Replay Orchestration.
"""

import pytest
from core.schemas import (
    ResultCategory,
    ExploitPayload,
    VerificationVerdict,
    AttackHypothesis,
    TargetProgram
)
from core.candidate_lifecycle import (
    CandidateRecord,
    rank_candidates,
    select_candidate_for_replay,
    finalize_candidate_replay
)
from core.config import config


def make_dummy_candidate(
    candidate_id: str,
    category: ResultCategory,
    reward_score: float,
    generation_iteration: int = 0,
    candidate_index: int = 0,
    is_verified: bool = False,
    reproducible: bool = False
) -> CandidateRecord:
    hyp = AttackHypothesis(
        vulnerability_type="ReentrancyDrain",
        reasoning_trace="Test trace",
        attack_vector="test vector"
    )
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=hyp,
        test_code=f"// Exploit {candidate_id}",
        candidate_id=candidate_id,
        generation_iteration=generation_iteration,
        candidate_index=candidate_index
    )
    verdict = VerificationVerdict(
        target_name="Vault",
        is_verified=is_verified,
        reward_score=reward_score,
        category=category,
        vulnerability_type="ReentrancyDrain",
        poc_code=f"// Exploit {candidate_id}",
        feedback="Test feedback",
        reproducible=reproducible,
        candidate_id=candidate_id,
        generation_iteration=generation_iteration,
        candidate_index=candidate_index
    )
    return CandidateRecord(
        candidate_id=candidate_id,
        run_id="run-test",
        target_name="Vault",
        generation_iteration=generation_iteration,
        candidate_index=candidate_index,
        payload=payload,
        verdict=verdict,
        replay_eligible=(category == ResultCategory.INVARIANT_BREACH_UNREPLAYED),
        reproduced=reproducible
    )


def test_candidate_0_revert_candidate_1_breach_selected():
    """Regression test 1: Candidate 0 = RUNTIME_REVERT; candidate 1 = INVARIANT_BREACH_UNREPLAYED.
    Candidate 1 must be selected and replayed, not silently falling back to 0."""
    cand0 = make_dummy_candidate("c0", ResultCategory.RUNTIME_REVERT, -0.25, candidate_index=0)
    cand1 = make_dummy_candidate("c1", ResultCategory.INVARIANT_BREACH_UNREPLAYED, 0.50, candidate_index=1)

    candidates = [cand0, cand1]
    selected = select_candidate_for_replay(candidates)

    assert selected is not None
    assert selected.candidate_id == "c1"
    assert selected.verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED


def test_refinement_candidate_is_considered_and_replayed():
    """Regression test 2: A successful candidate generated during refinement must be considered and replayed."""
    c0 = make_dummy_candidate("c0", ResultCategory.RUNTIME_REVERT, -0.25, generation_iteration=0)
    c1 = make_dummy_candidate("c1", ResultCategory.COMPILATION_ERROR, -0.50, generation_iteration=0)
    c_ref1 = make_dummy_candidate("ref1", ResultCategory.RUNTIME_REVERT, -0.25, generation_iteration=1)
    c_ref2 = make_dummy_candidate("ref2", ResultCategory.INVARIANT_BREACH_UNREPLAYED, 0.50, generation_iteration=2)

    all_candidates = [c0, c1, c_ref1, c_ref2]
    selected = select_candidate_for_replay(all_candidates)

    assert selected is not None
    assert selected.candidate_id == "ref2"
    assert selected.generation_iteration == 2


def test_replay_payload_and_verdict_have_same_candidate_id():
    """Regression test 3: Replay payload and selected verdict must have the exact same candidate ID."""
    cand = make_dummy_candidate("target_c7", ResultCategory.INVARIANT_BREACH_UNREPLAYED, 0.50)
    
    assert cand.candidate_id == cand.payload.candidate_id
    assert cand.candidate_id == cand.verdict.candidate_id

    finalized = finalize_candidate_replay(cand, replay_success=True)
    assert finalized.candidate_id == finalized.payload.candidate_id
    assert finalized.candidate_id == finalized.verdict.candidate_id


def test_replay_failure_never_reported_as_exploit_confirmed():
    """Regression test 4: Replay failure must never be reported as EXPLOIT_CONFIRMED."""
    cand = make_dummy_candidate("flaky_c1", ResultCategory.INVARIANT_BREACH_UNREPLAYED, 0.50)

    finalized = finalize_candidate_replay(cand, replay_success=False)

    assert finalized.verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert finalized.verdict.category != ResultCategory.EXPLOIT_CONFIRMED
    assert finalized.verdict.is_verified is False
    assert finalized.verdict.reproducible is False
    assert finalized.verdict.reward_score == config.REWARD_BREACH_NO_REPLAY  # 0.50


def test_no_candidate_silently_dropped_from_audit_record():
    """Regression test 5: No candidate must be silently dropped from the collection."""
    c0 = make_dummy_candidate("c0", ResultCategory.GENERATION_FORMAT_ERROR, -0.50)
    c1 = make_dummy_candidate("c1", ResultCategory.RUNTIME_REVERT, -0.25)
    c2 = make_dummy_candidate("c2", ResultCategory.INVARIANT_BREACH_UNREPLAYED, 0.50)
    c_ref = make_dummy_candidate("ref1", ResultCategory.SAFE_RUN, -0.10, generation_iteration=1)

    collection = [c0, c1, c2, c_ref]
    ranked = rank_candidates(collection)

    assert len(ranked) == 4
    # Highest ranked should be INVARIANT_BREACH_UNREPLAYED
    assert ranked[0].candidate_id == "c2"
    # Second should be SAFE_RUN
    assert ranked[1].candidate_id == "ref1"
    # Third should be RUNTIME_REVERT
    assert ranked[2].candidate_id == "c1"
    # Fourth should be GENERATION_FORMAT_ERROR
    assert ranked[3].candidate_id == "c0"


def test_no_eligible_candidate_returns_none():
    """Regression test 6: If no candidate breached invariant, select_candidate_for_replay returns None."""
    c0 = make_dummy_candidate("c0", ResultCategory.RUNTIME_REVERT, -0.25)
    c1 = make_dummy_candidate("c1", ResultCategory.COMPILATION_ERROR, -0.50)

    selected = select_candidate_for_replay([c0, c1])
    assert selected is None
