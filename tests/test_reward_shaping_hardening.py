"""
tests/test_reward_shaping_hardening.py

Reward Shaping Hardening (Reward Specification 2.0.0).

Covers the four properties the specification has to guarantee:

1. the reward is derived from TRUSTED evidence only - never from log text;
2. the reward is decomposed into five evidence-scoped components that sum up to
   the total (no double counting, no hidden re-weighting);
3. an unknown / untrusted outcome never yields a positive reward for a
   confirmed vulnerability (fail-closed);
4. trajectories scored by different reward specifications are never merged into
   one GRPO advantage group, and the reward stays reproducible from the stored
   components.
"""

import pytest

from core.candidate_lifecycle import (
    CandidateRecord,
    finalize_candidate_replay,
    create_finalized_trajectory,
)
from core.config import config
from core.evaluator import evaluate_execution_trace
from core.grpo_trainer import (
    group_rollouts_by_prompt,
    make_group_key,
    verify_reward_reproducibility,
)
from core.reward_shaping import (
    LEGACY_REWARD_SPEC_VERSION,
    REWARD_SPEC_VERSION,
    RewardComponent,
    RewardEvidence,
    compute_reward_breakdown,
    expected_total_for_category,
    verify_breakdown_consistency,
)
from core.schemas import (
    AttackHypothesis,
    ExploitPayload,
    ExecutionResult,
    ResultCategory,
    TargetProgram,
    VerificationVerdict,
)

BREACH_MARKER = "[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"


def make_payload(format_valid: bool = True) -> ExploitPayload:
    return ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="reentrancy in withdrawAll",
            attack_vector="receive() callback",
        ),
        test_code="contract ExploitModule { constructor(address a) payable {} function runExploit() external payable {} }",
        format_valid=format_valid,
    )


def trusted_breach_result(replay_confirmed: bool = False) -> ExecutionResult:
    """A result that carries a genuine trusted harness verdict."""
    return ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit()",
        stderr="",
        execution_time_sec=0.5,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        test_status="Success",
        invariant_violated=True,
        harness_verdict="BREACH",
        harness_suite="test/VaultHarness.t.sol",
        evidence_source="trusted_harness_structured_result",
        decoded_logs=[BREACH_MARKER],
        reproducibility_confirmed=replay_confirmed,
    )


# =============================================================================
# 1. TRUSTED EVIDENCE: NO REWARD FROM LOG TEXT
# =============================================================================

def test_log_marker_alone_never_produces_a_positive_reward():
    """
    The breach marker is printed by the model-controlled exploit itself.

    A result that only carries the marker (and no trusted harness verdict) must
    not be rewarded as a confirmed exploit.
    """
    result = ExecutionResult(
        return_code=0,
        stdout="",
        stderr="",
        execution_time_sec=0.2,
        invariant_violated=False,
        test_status="Success",
        decoded_logs=[BREACH_MARKER],
    )

    verdict = evaluate_execution_trace(make_payload(), result)

    assert verdict.is_verified is False
    assert verdict.reward_score < 0.0
    assert verdict.category != ResultCategory.EXPLOIT_CONFIRMED
    assert verdict.reward_components[RewardComponent.INVARIANT.value] == 0.0
    assert verdict.reward_components[RewardComponent.REPLAY.value] == 0.0


def test_false_positive_verdict_is_rejected():
    """
    A claimed breach that the trusted harness contradicts is a false positive.

    It must not be rewarded, and it must not be marked as verified.
    """
    result = ExecutionResult(
        return_code=0,
        stdout="",
        stderr="",
        execution_time_sec=0.3,
        invariant_violated=True,          # stale / forged flag
        test_status="Success",
        harness_verdict="NO_BREACH",      # the trusted harness says otherwise
        harness_suite="test/VaultHarness.t.sol",
        decoded_logs=[BREACH_MARKER],
    )

    verdict = evaluate_execution_trace(make_payload(), result)

    assert verdict.is_verified is False
    assert verdict.reward_score < 0.0
    assert verdict.category != ResultCategory.EXPLOIT_CONFIRMED
    assert verdict.category != ResultCategory.INVARIANT_BREACH_UNREPLAYED


def test_missing_trusted_evidence_never_confirms_an_exploit():
    """
    Fail-closed: without an explicit trusted verdict nothing is confirmed, even
    when every other signal claims a breach.
    """
    result = ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit()",
        stderr="",
        execution_time_sec=0.3,
        invariant_violated=True,
        test_status="Success",
        harness_verdict="",              # no trusted verdict at all
        decoded_logs=[BREACH_MARKER],
    )

    verdict = evaluate_execution_trace(make_payload(), result)

    assert verdict.is_verified is False
    assert verdict.reward_score <= 0.0
    assert verdict.reward_components[RewardComponent.INVARIANT.value] == 0.0


def test_unknown_harness_verdict_is_fail_closed():
    """An UNKNOWN verdict behaves like missing evidence."""
    result = ExecutionResult(
        return_code=0,
        stdout="",
        stderr="",
        execution_time_sec=0.3,
        invariant_violated=False,
        test_status="Success",
        harness_verdict="UNKNOWN",
    )

    verdict = evaluate_execution_trace(make_payload(), result)

    assert verdict.is_verified is False
    assert verdict.reward_components[RewardComponent.INVARIANT.value] == 0.0


# =============================================================================
# 2. COMPONENT DECOMPOSITION
# =============================================================================

def test_confirmed_exploit_is_decomposed_into_all_five_components():
    """A fully confirmed exploit credits every evidence class exactly once."""
    verdict = evaluate_execution_trace(make_payload(), trusted_breach_result(replay_confirmed=True))

    assert verdict.category == ResultCategory.EXPLOIT_CONFIRMED
    assert verdict.reward_spec_version == REWARD_SPEC_VERSION
    assert verdict.reward_components == {
        RewardComponent.GENERATION.value: config.REWARD_COMPONENT_GENERATION,
        RewardComponent.COMPILATION.value: config.REWARD_COMPONENT_COMPILATION,
        RewardComponent.VERIFICATION.value: config.REWARD_COMPONENT_VERIFICATION,
        RewardComponent.INVARIANT.value: config.REWARD_COMPONENT_INVARIANT,
        RewardComponent.REPLAY.value: config.REWARD_COMPONENT_REPLAY,
    }
    assert verdict.reward_score == config.REWARD_INVARIANT_BREACH
    assert verdict.reward_score == 1.0


def test_unreplayed_breach_has_no_replay_component():
    """Without an independent replay the replay component stays empty."""
    verdict = evaluate_execution_trace(make_payload(), trusted_breach_result(replay_confirmed=False))

    assert verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert verdict.reward_components[RewardComponent.REPLAY.value] == 0.0
    assert verdict.reward_components[RewardComponent.INVARIANT.value] > 0.0
    assert verdict.reward_score == config.REWARD_BREACH_NO_REPLAY
    assert verdict.reward_score == 0.5


def test_total_always_equals_components_plus_penalty():
    """The attribution is exact: total = sum(components) + penalty."""
    cases = [
        (ResultCategory.GENERATION_FORMAT_ERROR, RewardEvidence()),
        (ResultCategory.CHEATCODE_DETECTED, RewardEvidence()),
        (ResultCategory.INFRA_ERROR, RewardEvidence()),
        (ResultCategory.COMPILATION_ERROR, RewardEvidence(format_valid=True)),
        (ResultCategory.RUNTIME_REVERT, RewardEvidence(format_valid=True, compiled=True)),
        (ResultCategory.SAFE_RUN, RewardEvidence(format_valid=True, compiled=True, executed=True)),
        (
            ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            RewardEvidence(format_valid=True, compiled=True, executed=True, invariant_confirmed=True),
        ),
        (
            ResultCategory.EXPLOIT_CONFIRMED,
            RewardEvidence(
                format_valid=True, compiled=True, executed=True,
                invariant_confirmed=True, replay_confirmed=True,
            ),
        ),
    ]

    for category, evidence in cases:
        breakdown = compute_reward_breakdown(category, evidence)
        assert verify_breakdown_consistency(breakdown), category
        assert breakdown.total == round(sum(breakdown.components.values()) + breakdown.penalty, 10)
        assert breakdown.total == expected_total_for_category(category), category


def test_reward_ladder_is_unchanged_for_every_category():
    """The observable ladder stays byte-compatible with the legacy constants."""
    assert expected_total_for_category(ResultCategory.EXPLOIT_CONFIRMED) == config.REWARD_INVARIANT_BREACH
    assert expected_total_for_category(ResultCategory.INVARIANT_BREACH_UNREPLAYED) == config.REWARD_BREACH_NO_REPLAY
    assert expected_total_for_category(ResultCategory.SAFE_RUN) == config.REWARD_SAFE_RUN
    assert expected_total_for_category(ResultCategory.RUNTIME_REVERT) == config.REWARD_RUNTIME_REVERT
    assert expected_total_for_category(ResultCategory.RUNTIME_REVERT, timed_out=True) == config.REWARD_TIMEOUT
    assert expected_total_for_category(ResultCategory.COMPILATION_ERROR) == config.REWARD_COMPILATION_FAIL
    assert expected_total_for_category(ResultCategory.GENERATION_FORMAT_ERROR) == config.REWARD_FORMAT_ERROR
    assert expected_total_for_category(ResultCategory.CHEATCODE_DETECTED) == config.REWARD_CHEATCODE_PENALTY
    assert expected_total_for_category(ResultCategory.INFRA_ERROR) == config.REWARD_INFRA_ERROR


def test_negative_rewards_exist_for_every_failure_mode():
    """False positives, invalid contracts and unconfirmed exploits are punished."""
    format_verdict = evaluate_execution_trace(
        make_payload(format_valid=False),
        ExecutionResult(
            return_code=-4, stdout="", stderr="", execution_time_sec=0.0,
            category=ResultCategory.GENERATION_FORMAT_ERROR,
        ),
    )
    cheatcode_verdict = evaluate_execution_trace(
        make_payload(),
        ExecutionResult(
            return_code=-3, stdout="", stderr="", execution_time_sec=0.0,
            category=ResultCategory.CHEATCODE_DETECTED, cheatcode_detected=True,
        ),
    )
    compile_verdict = evaluate_execution_trace(
        make_payload(),
        ExecutionResult(
            return_code=1, stdout="Error (7576): Undeclared identifier", stderr="",
            execution_time_sec=0.2, category=ResultCategory.COMPILATION_ERROR,
        ),
    )
    safe_verdict = evaluate_execution_trace(
        make_payload(),
        ExecutionResult(
            return_code=0, stdout="", stderr="", execution_time_sec=0.2,
            category=ResultCategory.SAFE_RUN, test_status="Success",
            harness_verdict="NO_BREACH",
        ),
    )

    for verdict in (format_verdict, cheatcode_verdict, compile_verdict, safe_verdict):
        assert verdict.reward_score < 0.0
        assert verdict.is_verified is False


def test_no_double_counting_between_invariant_and_replay():
    """
    The invariant credit comes from the first execution, the replay credit from a
    second, independent execution. Each evidence class is credited once.
    """
    without_replay = compute_reward_breakdown(
        ResultCategory.INVARIANT_BREACH_UNREPLAYED,
        RewardEvidence(format_valid=True, compiled=True, executed=True, invariant_confirmed=True),
    )
    with_replay = compute_reward_breakdown(
        ResultCategory.EXPLOIT_CONFIRMED,
        RewardEvidence(
            format_valid=True, compiled=True, executed=True,
            invariant_confirmed=True, replay_confirmed=True,
        ),
    )

    # The invariant credit is identical - the replay adds its OWN component.
    assert (
        without_replay.components[RewardComponent.INVARIANT.value]
        == with_replay.components[RewardComponent.INVARIANT.value]
    )
    assert with_replay.components[RewardComponent.REPLAY.value] == config.REWARD_COMPONENT_REPLAY
    assert with_replay.total - without_replay.total == config.REWARD_COMPONENT_REPLAY


def test_reward_is_deterministic():
    """The same evidence always yields the same reward and the same fingerprint."""
    evidence = RewardEvidence(
        format_valid=True, compiled=True, executed=True,
        invariant_confirmed=True, replay_confirmed=True,
    )
    first = compute_reward_breakdown(ResultCategory.EXPLOIT_CONFIRMED, evidence)
    second = compute_reward_breakdown(ResultCategory.EXPLOIT_CONFIRMED, evidence)

    assert first.total == second.total
    assert first.fingerprint() == second.fingerprint()


# =============================================================================
# 3. REPLAY OUTCOMES
# =============================================================================

def _replay_candidate(replay_confirmed: bool):
    payload = make_payload()
    payload.candidate_id = "cand_replay"
    verdict = evaluate_execution_trace(payload, trusted_breach_result(replay_confirmed=False))
    verdict.candidate_id = "cand_replay"
    return CandidateRecord(
        candidate_id="cand_replay",
        run_id="run-replay",
        target_name="Vault",
        payload=payload,
        verdict=verdict,
        model_id="m",
        checkpoint_id="base",
        prompt_text="PROMPT",
        prompt_hash="h" * 64,
        replay_eligible=True,
    )


def test_successful_replay_adds_the_replay_component():
    """A confirmed independent replay adds exactly one component."""
    candidate = _replay_candidate(replay_confirmed=True)

    finalized = finalize_candidate_replay(candidate, replay_success=True)

    assert finalized.verdict.category == ResultCategory.EXPLOIT_CONFIRMED
    assert finalized.verdict.reward_components[RewardComponent.REPLAY.value] == config.REWARD_COMPONENT_REPLAY
    assert finalized.verdict.reward_score == config.REWARD_INVARIANT_BREACH
    assert finalized.verdict.is_verified is True
    assert finalized.verdict.reward_spec_version == REWARD_SPEC_VERSION


def test_failed_replay_keeps_the_reward_below_the_confirmed_one():
    """A failed replay never reaches the confirmed reward and stays unverified."""
    candidate = _replay_candidate(replay_confirmed=False)

    finalized = finalize_candidate_replay(candidate, replay_success=False)

    assert finalized.verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert finalized.verdict.reward_components[RewardComponent.REPLAY.value] == 0.0
    assert finalized.verdict.reward_score == config.REWARD_BREACH_NO_REPLAY
    assert finalized.verdict.is_verified is False
    assert finalized.verdict.replay_status == "FAILED"


def test_replay_infrastructure_error_is_neutral():
    """An infrastructure failure during replay is neutral, not a model failure."""
    candidate = _replay_candidate(replay_confirmed=False)

    finalized = finalize_candidate_replay(candidate, replay_success=False, replay_infra_error=True)

    assert finalized.verdict.category == ResultCategory.INFRA_ERROR
    assert finalized.verdict.reward_score == config.REWARD_INFRA_ERROR
    assert finalized.verdict.reward_score == 0.0
    assert finalized.verdict.is_verified is False


# =============================================================================
# 4. PROVENANCE OF THE REWARD
# =============================================================================

def test_trajectory_carries_the_reward_attribution_and_spec_version():
    """The trajectory stores the components, the penalty and the spec version."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    candidate = _replay_candidate(replay_confirmed=True)
    finalize_candidate_replay(candidate, replay_success=True)

    trajectory = create_finalized_trajectory(candidate, target)

    assert trajectory.reward_spec_version == REWARD_SPEC_VERSION
    assert trajectory.reward_components[RewardComponent.REPLAY.value] == config.REWARD_COMPONENT_REPLAY
    assert trajectory.reward == trajectory.reward_score if hasattr(trajectory, "reward_score") else trajectory.reward
    assert round(sum(trajectory.reward_components.values()) + trajectory.reward_penalty, 10) == trajectory.reward


def test_reward_is_reproducible_from_the_stored_components():
    """The stored reward can be re-derived from the stored attribution."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    candidate = _replay_candidate(replay_confirmed=True)
    finalize_candidate_replay(candidate, replay_success=True)
    trajectory = create_finalized_trajectory(candidate, target)

    report = verify_reward_reproducibility(trajectory.model_dump())

    assert report["has_attribution"] is True
    assert report["reproducible"] is True
    assert report["recomputed_total"] == trajectory.reward
    assert report["reward_spec_version"] == REWARD_SPEC_VERSION


def test_reward_without_attribution_is_reported_as_not_reproducible():
    """Fail-closed: a trajectory without attribution is not 'reproducible'."""
    report = verify_reward_reproducibility(
        {"trajectory_id": "t", "reward": 1.0, "reward_components": {}, "reward_penalty": 0.0}
    )

    assert report["has_attribution"] is False
    assert report["reproducible"] is False
    assert report["reason"] == "missing_reward_attribution"


# =============================================================================
# 5. GRPO COMPATIBILITY
# =============================================================================

def _rollout(idx, reward, spec_version, category="SAFE_RUN"):
    return {
        "candidate_id": f"c{idx}",
        "run_id": "r1",
        "target_name": "Vault",
        "prompt_used": "SAME PROMPT",
        "model_id": "m",
        "checkpoint_id": "base",
        "reward": reward,
        "category": category,
        "reward_spec_version": spec_version,
        "reward_components": {"generation": 0.05, "compilation": 0.10},
        "full_completion_text": "x",
        "generated_exploit": "y",
    }


def test_incompatible_reward_spec_versions_are_never_merged():
    """
    Rewards produced by different specifications are not comparable, so the
    trajectories must not share one advantage group.
    """
    dataset = [
        _rollout(0, 1.0, "2.0.0", "EXPLOIT_CONFIRMED"),
        _rollout(1, 1.0, "2.0.0", "EXPLOIT_CONFIRMED"),
        _rollout(2, 0.5, "1.0.0-legacy", "INVARIANT_BREACH_UNREPLAYED"),
        _rollout(3, 0.5, "1.0.0-legacy", "INVARIANT_BREACH_UNREPLAYED"),
    ]

    groups = group_rollouts_by_prompt(dataset, group_size=4)

    assert len(groups) == 2
    versions = sorted(g.reward_spec_version for g in groups)
    assert versions == ["1.0.0-legacy", "2.0.0"]
    for group in groups:
        assert len(group.rollouts) == 2
        # Every rollout of a group shares the group's specification version.
        assert all(r.reward_spec_version == group.reward_spec_version for r in group.rollouts)


def test_group_key_separates_reward_spec_versions():
    """The group identity itself carries the reward specification version."""
    prompt = "Same prompt"

    current = make_group_key("Vault", prompt, "m", "base", "2.0.0")
    legacy = make_group_key("Vault", prompt, "m", "base", "1.0.0-legacy")

    assert current != legacy


def test_trajectories_without_spec_version_are_treated_as_legacy():
    """Records written before the specification existed are isolated as legacy."""
    dataset = [
        {"candidate_id": "a", "target_name": "Vault", "prompt_used": "P", "reward": 1.0,
         "category": "EXPLOIT_CONFIRMED", "full_completion_text": "x", "generated_exploit": "y"},
        {"candidate_id": "b", "target_name": "Vault", "prompt_used": "P", "reward": 1.0,
         "category": "EXPLOIT_CONFIRMED", "full_completion_text": "x", "generated_exploit": "y"},
        _rollout(2, 1.0, "2.0.0", "EXPLOIT_CONFIRMED"),
        _rollout(3, 1.0, "2.0.0", "EXPLOIT_CONFIRMED"),
    ]

    groups = group_rollouts_by_prompt(dataset, group_size=4)

    assert len(groups) == 2
    versions = sorted(g.reward_spec_version for g in groups)
    assert versions == [LEGACY_REWARD_SPEC_VERSION, "2.0.0"]


def test_rollouts_preserve_the_reward_components():
    """The attribution survives the grouping into GRPO rollouts."""
    dataset = [
        _rollout(0, 1.0, "2.0.0", "EXPLOIT_CONFIRMED"),
        _rollout(1, -0.25, "2.0.0", "RUNTIME_REVERT"),
    ]

    groups = group_rollouts_by_prompt(dataset, group_size=2)

    assert len(groups) == 1
    rollout = groups[0].rollouts[0]
    assert rollout.reward_components["generation"] == 0.05
    assert rollout.reward_components["compilation"] == 0.10
    assert rollout.reward_spec_version == "2.0.0"


def test_grpo_architecture_is_unchanged():
    """The grouping still works exactly as before - only the key got stricter."""
    dataset = [
        _rollout(0, -0.5, "2.0.0", "COMPILATION_ERROR"),
        _rollout(1, -0.5, "2.0.0", "COMPILATION_ERROR"),
        _rollout(2, -0.1, "2.0.0", "SAFE_RUN"),
        _rollout(3, 1.0, "2.0.0", "EXPLOIT_CONFIRMED"),
    ]

    groups = group_rollouts_by_prompt(dataset, group_size=4)

    assert len(groups) == 1
    advantages = [r.advantage for r in groups[0].rollouts]
    # A mixed group must still produce a usable gradient.
    assert any(abs(a) > 0.0 for a in advantages)
    assert groups[0].std_reward > 0.0


# =============================================================================
# 6. REAL RECORDED VERIFICATION OUTCOMES
# =============================================================================

def _load_real_ab_candidates():
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "benchmarks" / "raw_ab_candidates.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_real_recorded_outcomes_are_rescored_consistently():
    """
    The real outcomes recorded by the A/B benchmark are re-scored with the
    current reward specification.

    The recorded rewards belong to the LEGACY specification (they were produced
    before the format/compilation split). The current specification rescores
    them deterministically, and the difference is exactly the documented ladder
    change - never an accident.
    """
    candidates = _load_real_ab_candidates()
    assert candidates, "no recorded candidates found"

    legacy_totals = {
        ResultCategory.GENERATION_FORMAT_ERROR.value: -0.50,   # legacy: format == compile
        ResultCategory.COMPILATION_ERROR.value: -0.50,
    }

    for candidate in candidates:
        verdict = candidate["verdict"]
        category = ResultCategory(verdict["category"])

        # 1. The recorded reward matches the legacy ladder it was produced with.
        assert verdict["reward_score"] == legacy_totals[category.value]

        # 2. The current specification rescores it deterministically.
        evidence = RewardEvidence(
            format_valid=(category != ResultCategory.GENERATION_FORMAT_ERROR),
            compiled=(category != ResultCategory.COMPILATION_ERROR),
        )
        breakdown = compute_reward_breakdown(category, evidence)

        assert verify_breakdown_consistency(breakdown)
        assert breakdown.total == expected_total_for_category(category)
        if category == ResultCategory.GENERATION_FORMAT_ERROR:
            # The documented ladder change: a format failure is strictly cheaper
            # to repair than a compilation failure.
            assert breakdown.total == config.REWARD_FORMAT_ERROR
            assert breakdown.total > config.REWARD_COMPILATION_FAIL
        else:
            assert breakdown.total == verdict["reward_score"]


def test_real_recorded_outcomes_carry_no_confirmed_exploit():
    """
    The real benchmark data contains no confirmed exploit - and under the new
    specification none of them can acquire one without a trusted harness verdict.
    """
    candidates = _load_real_ab_candidates()

    for candidate in candidates:
        verdict = candidate["verdict"]
        assert verdict["is_verified"] is False
        assert verdict["category"] != ResultCategory.EXPLOIT_CONFIRMED.value
        # No trusted harness verdict was recorded -> nothing can be confirmed.
        breakdown = compute_reward_breakdown(
            ResultCategory(verdict["category"]),
            RewardEvidence(format_valid=True),
        )
        assert breakdown.components[RewardComponent.INVARIANT.value] == 0.0
        assert breakdown.components[RewardComponent.REPLAY.value] == 0.0
