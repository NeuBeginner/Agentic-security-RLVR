"""
tests/test_round5_2_data_isolation.py

Regression tests for AI Supervisor Round 5.2 Blocker 3:
Isolation of synthetic/control trajectories from production GRPO datasets.

Verifies:
1. Schema & provenance invariants (dataset_partition, is_synthetic, token_provenance, trainable).
2. Synthetic positive control trajectories cannot enter production GRPO dataset.
3. Test partition records cannot enter production dataset.
4. Valid production records pass eligibility filter.
5. Missing or invalid provenance records are rejected fail-closed.
6. Test harness enforces synthetic_control partition and trainable=False.
7. Read-only storage audit accurately counts partitions and statuses without modifying files.
"""

import os
import json
import pytest
from core.schemas import (
    RLVRTrajectory,
    ResultCategory,
    TargetProgram,
    ExploitPayload,
    VerificationVerdict,
    AttackHypothesis
)
from core.candidate_lifecycle import (
    CandidateRecord,
    create_finalized_trajectory,
    compute_prompt_hash
)
from core.evaluator import create_trajectory_record
from core.grpo_trainer import (
    load_trajectories_from_directory,
    audit_trajectory_storage
)


def _make_dummy_target():
    return TargetProgram(
        name="Vault",
        source_code="contract Vault { mapping(address => uint256) public balances; }",
        language="solidity",
        invariants=["solvency"]
    )


def _make_dummy_payload(cand_id="cand_1", prompt_text="dummy prompt"):
    return ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Analysis trace",
            attack_vector="Drain"
        ),
        test_code="contract ExploitModule { constructor(address a) {} function runExploit() external {} }",
        candidate_id=cand_id,
        run_id="run_test",
        prompt_text=prompt_text,
        raw_model_response="Raw response with reasoning",
        generated_token_ids=[101, 102, 103]
    )


def test_schema_provenance_validation():
    """Validates schema enforcement on provenance attributes."""
    target = _make_dummy_target()
    payload = _make_dummy_payload()
    verdict = VerificationVerdict(
        target_name=target.name,
        is_verified=True,
        reward_score=1.0,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="Verified exploit",
        reproducible=True,
        replay_status="CONFIRMED"
    )

    # 1. Invalid partition must raise ValueError
    with pytest.raises(ValueError, match="invalid dataset_partition"):
        RLVRTrajectory(
            trajectory_id="traj_invalid_part",
            candidate_id="c1",
            run_id="r1",
            target_name=target.name,
            target_code=target.source_code,
            prompt_hash="dummy_hash",
            hypothesis=payload.hypothesis,
            generated_exploit=payload.test_code,
            reward=1.0,
            category=ResultCategory.EXPLOIT_CONFIRMED,
            is_verified=True,
            reproduced=True,
            feedback_trace="fb",
            dataset_partition="invalid_partition_name"
        )

    # 2. Synthetic trajectory cannot have dataset_partition='production'
    with pytest.raises(ValueError, match="synthetic trajectories cannot have dataset_partition='production'"):
        RLVRTrajectory(
            trajectory_id="traj_invalid_synth_prod",
            candidate_id="c1",
            run_id="r1",
            target_name=target.name,
            target_code=target.source_code,
            prompt_hash="dummy_hash",
            hypothesis=payload.hypothesis,
            generated_exploit=payload.test_code,
            reward=1.0,
            category=ResultCategory.EXPLOIT_CONFIRMED,
            is_verified=True,
            reproduced=True,
            feedback_trace="fb",
            dataset_partition="production",
            is_synthetic=True,
            trainable=False
        )

    # 3. Synthetic trajectory cannot have trainable=True
    with pytest.raises(ValueError, match="synthetic trajectories cannot have trainable=True"):
        RLVRTrajectory(
            trajectory_id="traj_invalid_synth_train",
            candidate_id="c1",
            run_id="r1",
            target_name=target.name,
            target_code=target.source_code,
            prompt_hash="dummy_hash",
            hypothesis=payload.hypothesis,
            generated_exploit=payload.test_code,
            reward=1.0,
            category=ResultCategory.EXPLOIT_CONFIRMED,
            is_verified=True,
            reproduced=True,
            feedback_trace="fb",
            dataset_partition="synthetic_control",
            is_synthetic=True,
            trainable=True
        )

    # 4. INFRA_ERROR cannot have trainable=True
    with pytest.raises(ValueError, match="INFRA_ERROR trajectories cannot have trainable=True"):
        RLVRTrajectory(
            trajectory_id="traj_invalid_infra_train",
            candidate_id="c1",
            run_id="r1",
            target_name=target.name,
            target_code=target.source_code,
            prompt_hash="dummy_hash",
            hypothesis=payload.hypothesis,
            generated_exploit=payload.test_code,
            reward=0.0,
            category=ResultCategory.INFRA_ERROR,
            is_verified=False,
            reproduced=False,
            feedback_trace="fb",
            dataset_partition="production",
            is_synthetic=False,
            trainable=True
        )


def test_synthetic_positive_control_not_in_production_dataset(tmp_path):
    """Proves synthetic positive control trajectories cannot enter production GRPO dataset."""
    target = _make_dummy_target()
    payload = _make_dummy_payload(cand_id="synth_pos_1")
    verdict = VerificationVerdict(
        target_name=target.name,
        is_verified=True,
        reward_score=1.0,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="Verified exploit from control suite",
        reproducible=True,
        replay_status="CONFIRMED"
    )

    traj = create_trajectory_record(
        target=target,
        payload=payload,
        verdict=verdict,
        prompt_used="control prompt",
        dataset_split="control",
        dataset_partition="synthetic_control",
        is_synthetic=True,
        token_provenance="synthetic",
        trainable=False
    )
    assert traj.is_synthetic is True
    assert traj.dataset_partition == "synthetic_control"
    assert traj.trainable is False

    # Persist to temporary volume directory
    fpath = tmp_path / f"traj_{traj.trajectory_id}.json"
    fpath.write_text(json.dumps(traj.model_dump(), indent=2), encoding="utf-8")

    # Load with production allowlist
    loaded = load_trajectories_from_directory(str(tmp_path), target_split="train", target_partition="production")
    assert len(loaded) == 0, "Synthetic control record must NEVER be loaded into production dataset!"


def test_test_partition_not_in_production_dataset(tmp_path):
    """Proves test-partition trajectories are excluded from production GRPO dataset."""
    target = _make_dummy_target()
    payload = _make_dummy_payload(cand_id="test_cand_1")
    verdict = VerificationVerdict(
        target_name=target.name,
        is_verified=False,
        reward_score=0.5,
        category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="Test unverified"
    )

    traj = create_trajectory_record(
        target=target,
        payload=payload,
        verdict=verdict,
        prompt_used="test prompt",
        dataset_split="test",
        dataset_partition="test",
        is_synthetic=False,
        token_provenance="model_generate",
        trainable=True
    )
    fpath = tmp_path / f"traj_{traj.trajectory_id}.json"
    fpath.write_text(json.dumps(traj.model_dump(), indent=2), encoding="utf-8")

    loaded = load_trajectories_from_directory(str(tmp_path), target_split="train", target_partition="production")
    assert len(loaded) == 0, "Test partition record must NOT be loaded into production dataset!"


def test_valid_production_record_passes_filter(tmp_path):
    """Proves valid production record passes the strict allowlist filter."""
    target = _make_dummy_target()
    payload = _make_dummy_payload(cand_id="prod_cand_1")
    verdict = VerificationVerdict(
        target_name=target.name,
        is_verified=True,
        reward_score=1.0,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="Confirmed exploit",
        reproducible=True,
        replay_status="CONFIRMED"
    )

    traj = create_trajectory_record(
        target=target,
        payload=payload,
        verdict=verdict,
        prompt_used="production prompt",
        dataset_split="train",
        dataset_partition="production",
        is_synthetic=False,
        token_provenance="model_generate",
        trainable=True
    )
    fpath = tmp_path / f"traj_{traj.trajectory_id}.json"
    fpath.write_text(json.dumps(traj.model_dump(), indent=2), encoding="utf-8")

    loaded = load_trajectories_from_directory(str(tmp_path), target_split="train", target_partition="production")
    assert len(loaded) == 1
    assert loaded[0]["candidate_id"] == "prod_cand_1"
    assert loaded[0]["dataset_partition"] == "production"
    assert loaded[0]["is_synthetic"] is False
    assert loaded[0]["trainable"] is True


def test_missing_provenance_rejected_fail_closed(tmp_path):
    """Legacy records lacking provenance fields must be rejected fail-closed."""
    target = _make_dummy_target()
    payload = _make_dummy_payload(cand_id="legacy_cand_1")
    
    # Raw dict without dataset_partition or is_synthetic
    legacy_data = {
        "trajectory_id": "traj_run_legacy_cand_1",
        "candidate_id": "legacy_cand_1",
        "run_id": "run_legacy",
        "target_name": target.name,
        "target_code": target.source_code,
        "prompt_hash": "dummy_hash",
        "generation_iteration": 0,
        "candidate_index": 1,
        "is_finalized": True,
        "replay_status": "NOT_ELIGIBLE",
        "timestamp": 1234567.0,
        "slither_hints": [],
        "prompt_used": "prompt",
        "hypothesis": payload.hypothesis.model_dump(),
        "full_completion_text": "completion",
        "generated_exploit": payload.test_code,
        "reward": 0.5,
        "category": "ResultCategory.INVARIANT_BREACH_UNREPLAYED",
        "is_verified": False,
        "reproduced": False,
        "feedback_trace": "trace",
        "dataset_split": "train"
        # dataset_partition and is_synthetic missing!
    }

    fpath = tmp_path / "traj_run_legacy_cand_1.json"
    fpath.write_text(json.dumps(legacy_data, indent=2), encoding="utf-8")

    loaded = load_trajectories_from_directory(str(tmp_path), target_split="train", target_partition="production")
    assert len(loaded) == 0, "Record missing provenance fields must be rejected fail-closed!"


def test_test_harness_enforces_synthetic_control():
    """Proves create_trajectory_record forces dataset_partition='synthetic_control' when is_synthetic=True."""
    target = _make_dummy_target()
    payload = _make_dummy_payload(cand_id="harness_control_cand")
    verdict = VerificationVerdict(
        target_name=target.name,
        is_verified=True,
        reward_score=1.0,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="Verified exploit",
        reproducible=True,
        replay_status="CONFIRMED"
    )

    # Attempt to erroneously pass dataset_partition='production' with is_synthetic=True
    traj = create_trajectory_record(
        target=target,
        payload=payload,
        verdict=verdict,
        prompt_used="prompt",
        dataset_partition="production",
        is_synthetic=True,
        trainable=True
    )
    # create_trajectory_record must automatically override partition to synthetic_control and trainable=False
    assert traj.is_synthetic is True
    assert traj.dataset_partition == "synthetic_control"
    assert traj.trainable is False
    assert traj.token_provenance == "synthetic"


def test_read_only_audit_storage(tmp_path):
    """Proves audit_trajectory_storage counts partitions accurately without modifying files."""
    target = _make_dummy_target()
    payload = _make_dummy_payload()
    verdict = VerificationVerdict(
        target_name=target.name,
        is_verified=False,
        reward_score=0.5,
        category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="fb"
    )

    # 1. Production record
    t_prod = create_trajectory_record(target, payload, verdict, "p1", dataset_split="train", dataset_partition="production", is_synthetic=False, trainable=True)
    (tmp_path / f"traj_{t_prod.trajectory_id}.json").write_text(json.dumps(t_prod.model_dump(), indent=2), encoding="utf-8")

    # 2. Synthetic control record
    t_synth = create_trajectory_record(target, payload, verdict, "p2", dataset_split="control", dataset_partition="synthetic_control", is_synthetic=True, trainable=False)
    t_synth.trajectory_id = "traj_synth_1"
    (tmp_path / f"traj_{t_synth.trajectory_id}.json").write_text(json.dumps(t_synth.model_dump(), indent=2), encoding="utf-8")

    # 3. Test record
    t_test = create_trajectory_record(target, payload, verdict, "p3", dataset_split="test", dataset_partition="test", is_synthetic=False, trainable=True)
    t_test.trajectory_id = "traj_test_1"
    (tmp_path / f"traj_{t_test.trajectory_id}.json").write_text(json.dumps(t_test.model_dump(), indent=2), encoding="utf-8")

    # 4. Malformed record
    (tmp_path / "traj_malformed_1.json").write_text("NOT A VALID JSON", encoding="utf-8")

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["total_files"] == 4
    assert audit["valid_schema_count"] == 3
    assert audit["malformed_count"] == 1
    assert audit["by_partition"]["production"] == 1
    assert audit["by_partition"]["synthetic_control"] == 1
    assert audit["by_partition"]["test"] == 1
    assert audit["by_synthetic"]["synthetic"] == 1
    assert audit["by_synthetic"]["non_synthetic"] == 2
    assert audit["production_eligible_for_grpo"] == 1
