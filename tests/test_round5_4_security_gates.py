"""
tests/test_round5_4_security_gates.py

Security and Boundary Verification for Round 5.4 Section 6:
Ensures fail-closed training gates, direct invocation restrictions,
and data partition isolation are strictly enforced.
"""

import os
import pytest
from core.grpo_trainer import (
    train_grpo_epochs,
    load_production_trajectories,
    load_trajectories_from_directory,
    group_rollouts_by_prompt
)
from core.schemas import GRPOGroup, GRPORollout, AttackHypothesis, ResultCategory


def test_train_grpo_epochs_fail_closed_gate():
    """Verifies that train_grpo_epochs cannot be executed when TRAINING_STATUS = BLOCKED."""
    os.environ["TRAINING_STATUS"] = "BLOCKED"
    with pytest.raises(RuntimeError, match="FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED"):
        train_grpo_epochs(
            model=None,
            optimizer=None,
            groups=[],
            tokenizer=None
        )


def test_default_loader_requires_exact_tokens_fail_closed():
    """Verifies that load_trajectories_from_directory has safe default require_exact_tokens=True."""
    import inspect
    sig = inspect.signature(load_trajectories_from_directory)
    assert sig.parameters["require_exact_tokens"].default is True
    assert sig.parameters["target_partition"].default == "production"
    assert sig.parameters["target_split"].default == "train"


def test_group_rollouts_excludes_synthetic_and_non_trainable():
    """Verifies that group_rollouts_by_prompt excludes synthetic and non-trainable rollouts."""
    prompt = "Audit Vault solvency"
    rollouts = [
        {
            "trajectory_id": "t1",
            "prompt_used": prompt,
            "reward": 1.0,
            "category": "EXPLOIT_CONFIRMED",
            "is_synthetic": True,  # Must be excluded!
            "trainable": False
        },
        {
            "trajectory_id": "t2",
            "prompt_used": prompt,
            "reward": 0.5,
            "category": "INVARIANT_BREACH_UNREPLAYED",
            "is_synthetic": False,
            "trainable": False  # Non-trainable, must be excluded!
        },
        {
            "trajectory_id": "t3",
            "prompt_used": prompt,
            "reward": 0.5,
            "category": "INVARIANT_BREACH_UNREPLAYED",
            "is_synthetic": False,
            "trainable": True
        },
        {
            "trajectory_id": "t4",
            "prompt_used": prompt,
            "reward": -0.5,
            "category": "COMPILATION_ERROR",
            "is_synthetic": False,
            "trainable": True
        }
    ]

    groups = group_rollouts_by_prompt(rollouts, group_size=2)
    assert len(groups) == 1
    # Only t3 and t4 should be included
    included_ids = {r.candidate_id for r in groups[0].rollouts}
    assert included_ids == {"t3", "t4"}


def test_validation_and_holdout_splits_never_enter_production_loader(tmp_path):
    """Verifies that validation and holdout splits are strictly rejected by load_production_trajectories."""
    import json

    def _make_split_traj(tid, cid, split):
        return {
            "trajectory_id": tid,
            "candidate_id": cid,
            "run_id": "run_test",
            "target_name": "Vault",
            "target_code": "contract Vault {}",
            "prompt_hash": "hash_test",
            "prompt_used": "Audit Vault",
            "hypothesis": {"vulnerability_type": "Reentrancy", "reasoning_trace": "", "attack_vector": ""},
            "generated_exploit": "contract Exploit {}",
            "reward": -0.25,
            "category": "RUNTIME_REVERT",
            "is_verified": False,
            "reproduced": False,
            "feedback_trace": "feedback",
            "dataset_split": split,
            "dataset_partition": "production",
            "is_synthetic": False,
            "token_provenance": "model_generate",
            "trainable": True,
            "is_finalized": True,
            "generated_token_ids": [101, 102]
        }

    val_traj = _make_split_traj("t_val", "c_val", "val")
    holdout_traj = _make_split_traj("t_holdout", "c_holdout", "holdout")

    (tmp_path / "traj_val.json").write_text(json.dumps(val_traj), encoding="utf-8")
    (tmp_path / "traj_holdout.json").write_text(json.dumps(holdout_traj), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path), target_split="train")
    assert len(loaded) == 0
