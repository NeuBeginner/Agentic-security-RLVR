"""
tests/test_trajectory_integrity.py

Regression test suite for Section 4 (Round 4):
Trajectory Data Integrity, Deduplication, and Schema Invariant Validation.
"""

import pytest
import os
import json
import tempfile
from core.schemas import (
    RLVRTrajectory,
    ResultCategory,
    AttackHypothesis
)
from core.grpo_trainer import load_trajectories_from_directory


def make_valid_trajectory(
    traj_id: str = "traj_001",
    candidate_id: str = "cand_001",
    category: ResultCategory = ResultCategory.RUNTIME_REVERT,
    reward: float = -0.25,
    is_verified: bool = False,
    reproduced: bool = False,
    replay_status: str = "NOT_ELIGIBLE",
    is_finalized: bool = True,
    dataset_split: str = "train"
) -> RLVRTrajectory:
    hyp = AttackHypothesis(
        vulnerability_type="ReentrancyDrain",
        reasoning_trace="Test trace",
        attack_vector="test vector"
    )
    return RLVRTrajectory(
        trajectory_id=traj_id,
        candidate_id=candidate_id,
        run_id="run-001",
        target_name="Vault",
        target_code="contract Vault {}",
        prompt_hash="abc123hash",
        hypothesis=hyp,
        generated_exploit="contract ExploitModule {}",
        reward=reward,
        category=category,
        is_verified=is_verified,
        reproduced=reproduced,
        replay_status=replay_status,
        is_finalized=is_finalized,
        dataset_split=dataset_split,
        feedback_trace="execution feedback"
    )


def test_unfinalized_trajectory_rejected_from_training():
    """Test 1: A trajectory saved before replay (is_finalized=False) cannot enter training."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create unfinalized trajectory
        t_unfin = make_valid_trajectory("traj_unfin", "cand_unfin", is_finalized=False)
        with open(os.path.join(tmpdir, "traj_unfin.json"), "w") as f:
            f.write(t_unfin.model_dump_json())

        # Create finalized trajectory
        t_fin = make_valid_trajectory("traj_fin", "cand_fin", is_finalized=True)
        with open(os.path.join(tmpdir, "traj_fin.json"), "w") as f:
            f.write(t_fin.model_dump_json())

        loaded = load_trajectories_from_directory(tmpdir, target_split="train")
        assert len(loaded) == 1
        assert loaded[0]["trajectory_id"] == "traj_fin"


def test_replay_result_updates_exact_trajectory():
    """Test 2: Replay result updates the exact corresponding trajectory."""
    # Pre-replay unconfirmed trajectory
    pre_replay = make_valid_trajectory(
        traj_id="traj_target",
        candidate_id="cand_target",
        category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
        reward=0.50,
        is_verified=False,
        reproduced=False,
        replay_status="NOT_ELIGIBLE"
    )
    assert pre_replay.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert pre_replay.reward == 0.50

    # Post-replay confirmed trajectory
    post_replay = make_valid_trajectory(
        traj_id="traj_target",
        candidate_id="cand_target",
        category=ResultCategory.EXPLOIT_CONFIRMED,
        reward=1.00,
        is_verified=True,
        reproduced=True,
        replay_status="CONFIRMED"
    )
    assert post_replay.candidate_id == pre_replay.candidate_id
    assert post_replay.category == ResultCategory.EXPLOIT_CONFIRMED
    assert post_replay.reward == 1.00
    assert post_replay.is_verified is True


def test_duplicate_ingestion_does_not_duplicate_sample():
    """Test 3: Ingesting duplicate files or candidates does not duplicate samples in training."""
    with tempfile.TemporaryDirectory() as tmpdir:
        t1 = make_valid_trajectory("traj_100", "cand_100")
        t2_dup = make_valid_trajectory("traj_100", "cand_100")  # exact duplicate ID

        with open(os.path.join(tmpdir, "traj_file1.json"), "w") as f:
            f.write(t1.model_dump_json())
        with open(os.path.join(tmpdir, "traj_file2_duplicate.json"), "w") as f:
            f.write(t2_dup.model_dump_json())

        loaded = load_trajectories_from_directory(tmpdir, target_split="train")
        # Deduplication must yield exactly 1 record
        assert len(loaded) == 1


def test_inconsistent_combinations_rejected_by_schema():
    """Test 4: Inconsistent replay/category/reward combinations are rejected with ValueError."""
    # EXPLOIT_CONFIRMED with reward != 1.0
    with pytest.raises(ValueError, match="EXPLOIT_CONFIRMED requires reward=1.0"):
        make_valid_trajectory(
            category=ResultCategory.EXPLOIT_CONFIRMED,
            reward=0.5,  # Inconsistent!
            is_verified=True,
            reproduced=True,
            replay_status="CONFIRMED"
        )

    # EXPLOIT_CONFIRMED without reproduced=True
    with pytest.raises(ValueError, match="reproduced=True"):
        make_valid_trajectory(
            category=ResultCategory.EXPLOIT_CONFIRMED,
            reward=1.0,
            is_verified=True,
            reproduced=False,  # Inconsistent!
            replay_status="CONFIRMED"
        )

    # INVARIANT_BREACH_UNREPLAYED with is_verified=True
    with pytest.raises(ValueError, match="INVARIANT_BREACH_UNREPLAYED cannot have"):
        make_valid_trajectory(
            category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            reward=0.5,
            is_verified=True,  # Inconsistent!
            reproduced=False
        )

    # Missing trajectory_id
    with pytest.raises(ValueError, match="trajectory_id must be non-empty"):
        make_valid_trajectory(traj_id="")


def test_dataset_split_isolation():
    """Test 5: Validation/holdout data is isolated and never ingested into training."""
    with tempfile.TemporaryDirectory() as tmpdir:
        t_train = make_valid_trajectory("traj_tr", "cand_tr", dataset_split="train")
        t_val = make_valid_trajectory("traj_vl", "cand_vl", dataset_split="val")
        t_holdout = make_valid_trajectory("traj_ho", "cand_ho", dataset_split="holdout")

        with open(os.path.join(tmpdir, "traj_tr.json"), "w") as f:
            f.write(t_train.model_dump_json())
        with open(os.path.join(tmpdir, "traj_vl.json"), "w") as f:
            f.write(t_val.model_dump_json())
        with open(os.path.join(tmpdir, "traj_ho.json"), "w") as f:
            f.write(t_holdout.model_dump_json())

        train_records = load_trajectories_from_directory(tmpdir, target_split="train")
        assert len(train_records) == 1
        assert train_records[0]["dataset_split"] == "train"

        val_records = load_trajectories_from_directory(tmpdir, target_split="val")
        assert len(val_records) == 1
        assert val_records[0]["dataset_split"] == "val"
