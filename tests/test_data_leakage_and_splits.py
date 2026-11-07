"""
tests/test_data_leakage_and_splits.py

Test Suite for Stage 3: GRPO Dataset Integrity, Data Leakage Prevention, and Split Isolation.
Tests:
1. Target/Protocol disjointness (train vs test/holdout).
2. Exploit hash disjointness across splits.
3. Synthetic control isolation.
4. Grounding of EXPLOIT_CONFIRMED records.
5. Deduplication and training gate validation.
"""

import os
import pytest
from core.grpo_trainer import (
    validate_data_leakage_and_splits,
    DataLeakageError,
    train_grpo_epochs,
)
from core.schemas import ResultCategory


def test_clean_disjoint_dataset_passes_validation():
    """Validates that a correctly partitioned, disjoint dataset passes with 0 violations."""
    trajectories = [
        {
            "trajectory_id": "traj_train_1",
            "candidate_id": "c1",
            "target_name": "Vault",
            "dataset_split": "train",
            "dataset_partition": "production",
            "is_synthetic": False,
            "trainable": True,
            "category": "SAFE_RUN",
            "generated_exploit": "contract Exploit1 {}"
        },
        {
            "trajectory_id": "traj_train_2",
            "candidate_id": "c2",
            "target_name": "Vault",
            "dataset_split": "train",
            "dataset_partition": "production",
            "is_synthetic": False,
            "trainable": True,
            "category": "EXPLOIT_CONFIRMED",
            "is_verified": True,
            "reproduced": True,
            "replay_status": "CONFIRMED",
            "generated_exploit": "contract Exploit2 {}"
        },
        {
            "trajectory_id": "traj_test_1",
            "candidate_id": "c3",
            "target_name": "ERC4626Vault",  # Different target from train!
            "dataset_split": "test",
            "dataset_partition": "production",
            "is_synthetic": False,
            "trainable": False,
            "category": "SAFE_RUN",
            "generated_exploit": "contract Exploit3 {}"  # Different exploit from train!
        }
    ]

    report = validate_data_leakage_and_splits(trajectories, raise_on_error=True)
    assert report["valid"] is True
    assert len(report["violations"]) == 0
    assert report["total_records"] == 3


def test_target_overlap_between_train_and_test_raises_leakage():
    """Detects protocol/target overlap between train and test splits."""
    trajectories = [
        {
            "trajectory_id": "traj_train_1",
            "target_name": "Vault",
            "dataset_split": "train",
            "dataset_partition": "production",
            "is_synthetic": False,
            "trainable": True,
            "category": "SAFE_RUN",
            "generated_exploit": "contract ExploitA {}"
        },
        {
            "trajectory_id": "traj_test_1",
            "target_name": "Vault",  # LEAK! Target in train is also in test!
            "dataset_split": "test",
            "dataset_partition": "production",
            "is_synthetic": False,
            "trainable": False,
            "category": "SAFE_RUN",
            "generated_exploit": "contract ExploitB {}"
        }
    ]

    report = validate_data_leakage_and_splits(trajectories, raise_on_error=False)
    assert report["valid"] is False
    assert any("Target contracts present in both 'train' and 'test'" in v for v in report["violations"])

    with pytest.raises(DataLeakageError):
        validate_data_leakage_and_splits(trajectories, raise_on_error=True)


def test_exploit_hash_overlap_between_train_and_test_detected():
    """Detects identical exploit code present in both train and test splits."""
    identical_exploit = "contract ExploitIdentical { function attack() public {} }"
    trajectories = [
        {
            "trajectory_id": "traj_train_1",
            "target_name": "TargetA",
            "dataset_split": "train",
            "dataset_partition": "production",
            "is_synthetic": False,
            "trainable": True,
            "category": "SAFE_RUN",
            "generated_exploit": identical_exploit
        },
        {
            "trajectory_id": "traj_test_1",
            "target_name": "TargetB",
            "dataset_split": "test",
            "dataset_partition": "production",
            "is_synthetic": False,
            "trainable": False,
            "category": "SAFE_RUN",
            "generated_exploit": identical_exploit  # LEAK! Same exploit code!
        }
    ]

    report = validate_data_leakage_and_splits(trajectories, raise_on_error=False)
    assert report["valid"] is False
    assert any("Exploit payloads duplicated across 'train' and 'test'" in v for v in report["violations"])


def test_synthetic_control_isolation_enforced():
    """Synthetic trajectories must never have dataset_partition='production' or trainable=True."""
    trajectories = [
        {
            "trajectory_id": "traj_synth_leak",
            "target_name": "Vault",
            "dataset_split": "train",
            "dataset_partition": "production",  # VIOLATION: synthetic in production
            "is_synthetic": True,
            "trainable": True,                   # VIOLATION: synthetic marked trainable
            "category": "SAFE_RUN",
            "generated_exploit": "contract Synth {}"
        }
    ]

    report = validate_data_leakage_and_splits(trajectories, raise_on_error=False)
    assert report["valid"] is False
    assert any("Synthetic trajectory" in v for v in report["violations"])


def test_ungrounded_exploit_confirmed_flagged():
    """Catches trajectories claiming EXPLOIT_CONFIRMED without replay confirmation."""
    trajectories = [
        {
            "trajectory_id": "traj_unreplayed_claim",
            "target_name": "Vault",
            "dataset_split": "train",
            "dataset_partition": "production",
            "is_synthetic": False,
            "trainable": True,
            "category": "EXPLOIT_CONFIRMED",
            "is_verified": False,              # VIOLATION: not verified
            "reproduced": False,               # VIOLATION: not reproduced
            "replay_status": "NOT_ELIGIBLE",   # VIOLATION: replay not confirmed
            "generated_exploit": "contract Exploit {}"
        }
    ]

    report = validate_data_leakage_and_splits(trajectories, raise_on_error=False)
    assert report["valid"] is False
    assert any("failed grounding" in v for v in report["violations"])


def test_fail_closed_training_gate_blocks_optimizer():
    """Confirms that the fail-closed training gate blocks execution when TRAINING_STATUS = BLOCKED."""
    os.environ["TRAINING_STATUS"] = "BLOCKED"
    with pytest.raises(RuntimeError, match="FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED"):
        train_grpo_epochs(
            model=None,
            optimizer=None,
            groups=[],
            tokenizer=None
        )
