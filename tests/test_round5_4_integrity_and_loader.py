"""
tests/test_round5_4_integrity_and_loader.py

Mandatory Regression Test Suite for Round 5.4:
AEGIS-RLVR GRPO Data Integrity, Exact Token Lineage, and Loader Hardening.

Covers all 17 mandatory acceptance test cases specified by AI Supervisor:
 1. Production + model_generate + valid token IDs + finalized -> accepted.
 2. Production + external_text_only -> rejected.
 3. Production + missing token_provenance -> rejected.
 4. Production + missing generated_token_ids -> rejected.
 5. Production + empty generated_token_ids -> rejected.
 6. Synthetic trajectory -> rejected.
 7. Missing dataset_partition -> rejected.
 8. Missing is_synthetic -> rejected.
 9. Unfinalized trajectory -> rejected.
10. Validation error -> rejected with exact reason.
11. INFRA_ERROR -> rejected.
12. Validation defaults never turn missing raw fields into eligible production records.
13. Duplicate trajectory_id -> not reloaded.
14. Duplicate candidate_id -> not reloaded.
15. Audit eligibility matches real loader eligibility.
16. Exact-token eligibility matches strict production loader.
17. Historical 3 production vs 6 eligible discrepancy reproduced and resolved.
"""

import json
import pytest
from core.schemas import ResultCategory, RLVRTrajectory
from core.grpo_trainer import (
    evaluate_trajectory_eligibility,
    load_production_trajectories,
    load_trajectories_from_directory,
    legacy_load_trajectories_for_inspection,
    audit_trajectory_storage
)


def _build_valid_raw_trajectory(
    traj_id="traj_prod_001",
    cand_id="cand_prod_001",
    category="RUNTIME_REVERT",
    reward=-0.25,
    is_verified=False,
    reproduced=False,
    replay_status="NOT_ELIGIBLE",
    is_finalized=True,
    dataset_partition="production",
    is_synthetic=False,
    trainable=True,
    token_provenance="model_generate",
    dataset_split="train",
    generated_token_ids=None
):
    """Constructs a fully populated, raw dictionary representing a valid trajectory file."""
    if generated_token_ids is None:
        generated_token_ids = [101, 102, 103, 104]

    return {
        "trajectory_id": traj_id,
        "candidate_id": cand_id,
        "run_id": "run_2026_01",
        "target_name": "Vault",
        "target_code": "contract Vault { mapping(address => uint256) public balances; }",
        "prompt_hash": "hash_abc123",
        "generation_iteration": 0,
        "candidate_index": 0,
        "evaluator_version": "v2.0",
        "is_finalized": is_finalized,
        "replay_status": replay_status,
        "timestamp": 1793476000.0,
        "prompt_used": "Audit Vault contract for security invariant breaches.",
        "hypothesis": {
            "vulnerability_type": "ReentrancyDrain",
            "reasoning_trace": "Analysis trace here",
            "attack_vector": "Call withdrawAll"
        },
        "full_completion_text": "Detailed model completion trace...",
        "generated_exploit": "contract ExploitModule { function runExploit() external {} }",
        "reward": reward,
        "category": category,
        "is_verified": is_verified,
        "reproduced": reproduced,
        "feedback_trace": "Harness execution trace",
        "dataset_split": dataset_split,
        "dataset_partition": dataset_partition,
        "is_synthetic": is_synthetic,
        "token_provenance": token_provenance,
        "trainable": trainable,
        "generated_token_ids": generated_token_ids
    }


# =============================================================================
# 17 MANDATORY REGRESSION TESTS
# =============================================================================

def test_case_01_production_valid_exact_tokens_finalized_accepted(tmp_path):
    """Case 1: Production + model_generate + valid token IDs + finalized is accepted."""
    raw = _build_valid_raw_trajectory()
    fpath = tmp_path / "traj_01.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 1
    assert loaded[0]["trajectory_id"] == "traj_prod_001"

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["total_files"] == 1
    assert audit["loader_eligible_count"] == 1
    assert audit["exact_token_eligible_count"] == 1
    assert audit["production_eligible_for_grpo"] == 1
    assert audit["rejected_count"] == 0


def test_case_02_production_external_text_only_rejected(tmp_path):
    """Case 2: Production + external_text_only is rejected from strict training."""
    raw = _build_valid_raw_trajectory(
        token_provenance="external_text_only",
        generated_token_ids=[101, 102]
    )
    fpath = tmp_path / "traj_02.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "token_provenance_not_model_generate_external_text_only" in audit["rejection_reasons"]


def test_case_03_production_missing_token_provenance_rejected(tmp_path):
    """Case 3: Production + missing token_provenance in raw JSON is rejected."""
    raw = _build_valid_raw_trajectory()
    del raw["token_provenance"]
    fpath = tmp_path / "traj_03.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "missing_raw_token_provenance" in audit["rejection_reasons"]


def test_case_04_production_missing_generated_token_ids_rejected(tmp_path):
    """Case 4: Production + missing generated_token_ids in raw JSON is rejected."""
    raw = _build_valid_raw_trajectory()
    del raw["generated_token_ids"]
    fpath = tmp_path / "traj_04.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "missing_raw_generated_token_ids" in audit["rejection_reasons"]


def test_case_05_production_empty_generated_token_ids_rejected(tmp_path):
    """Case 5: Production + empty generated_token_ids list is rejected."""
    raw = _build_valid_raw_trajectory(generated_token_ids=[])
    fpath = tmp_path / "traj_05.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "empty_generated_token_ids" in audit["rejection_reasons"]


def test_case_06_synthetic_trajectory_rejected(tmp_path):
    """Case 6: Synthetic control trajectory is rejected from GRPO training."""
    raw = _build_valid_raw_trajectory(
        dataset_partition="synthetic_control",
        is_synthetic=True,
        trainable=False,
        token_provenance="synthetic"
    )
    fpath = tmp_path / "traj_06.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "synthetic_trajectory" in audit["rejection_reasons"]


def test_case_07_missing_dataset_partition_rejected(tmp_path):
    """Case 7: Missing dataset_partition in raw JSON is rejected."""
    raw = _build_valid_raw_trajectory()
    del raw["dataset_partition"]
    fpath = tmp_path / "traj_07.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "missing_raw_dataset_partition" in audit["rejection_reasons"]


def test_case_08_missing_is_synthetic_rejected(tmp_path):
    """Case 8: Missing is_synthetic in raw JSON is rejected."""
    raw = _build_valid_raw_trajectory()
    del raw["is_synthetic"]
    fpath = tmp_path / "traj_08.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "missing_raw_is_synthetic" in audit["rejection_reasons"]


def test_case_09_unfinalized_trajectory_rejected(tmp_path):
    """Case 9: Unfinalized trajectory (is_finalized=False) is rejected."""
    raw = _build_valid_raw_trajectory(is_finalized=False)
    fpath = tmp_path / "traj_09.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "unfinalized_trajectory" in audit["rejection_reasons"]


def test_case_10_validation_error_rejected_with_exact_reason(tmp_path):
    """Case 10: Inconsistent combination (EXPLOIT_CONFIRMED with reward=0.5) is rejected with schema error."""
    raw = _build_valid_raw_trajectory(
        category=ResultCategory.EXPLOIT_CONFIRMED.value,
        reward=0.5,  # Inconsistent! Requires 1.0
        is_verified=True,
        reproduced=True,
        replay_status="CONFIRMED"
    )
    fpath = tmp_path / "traj_10.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert audit["schema_valid_count"] == 0
    # Exact reason must be captured
    reasons = list(audit["rejection_reasons"].keys())
    assert any("EXPLOIT_CONFIRMED requires reward=1.0" in r for r in reasons)


def test_case_11_infra_error_rejected(tmp_path):
    """Case 11: INFRA_ERROR trajectory is strictly rejected from training."""
    raw = _build_valid_raw_trajectory(
        category=ResultCategory.INFRA_ERROR.value,
        reward=0.0,
        is_verified=False,
        reproduced=False,
        trainable=False
    )
    fpath = tmp_path / "traj_11.json"
    fpath.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["rejected_count"] == 1
    assert "infra_error_category" in audit["rejection_reasons"]


def test_case_12_validation_defaults_never_fabricate_eligibility(tmp_path):
    """Case 12: Missing raw fields must never be turned into eligible production records via schema defaults."""
    # Legacy trajectory without provenance attributes
    legacy_raw = {
        "trajectory_id": "traj_legacy_001",
        "candidate_id": "cand_legacy_001",
        "run_id": "run_old",
        "target_name": "Vault",
        "target_code": "contract Vault {}",
        "prompt_hash": "hash_old",
        "hypothesis": {"vulnerability_type": "Reentrancy", "reasoning_trace": "", "attack_vector": ""},
        "generated_exploit": "contract Exploit {}",
        "reward": -0.25,
        "category": "RUNTIME_REVERT",
        "is_verified": False,
        "reproduced": False,
        "feedback_trace": "feedback"
        # dataset_partition, is_synthetic, trainable, is_finalized, token_provenance, generated_token_ids are ALL MISSING
    }
    fpath = tmp_path / "traj_legacy.json"
    fpath.write_text(json.dumps(legacy_raw), encoding="utf-8")

    # Raw inspection before schema must catch missing fields
    eval_res = evaluate_trajectory_eligibility(legacy_raw)
    assert eval_res["is_eligible"] is False
    assert eval_res["rejection_reason"] == "missing_raw_dataset_partition"

    # Loader must reject
    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 0

    # Audit must reject and not count as eligible
    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 0
    assert audit["production_eligible_for_grpo"] == 0
    assert audit["by_partition"]["missing_or_other"] == 1


def test_case_13_duplicate_trajectory_id_deduplicated(tmp_path):
    """Case 13: Duplicate trajectory_id is ingested only once."""
    raw1 = _build_valid_raw_trajectory(traj_id="traj_same_id", cand_id="cand_1")
    raw2 = _build_valid_raw_trajectory(traj_id="traj_same_id", cand_id="cand_2")

    (tmp_path / "traj_file_1.json").write_text(json.dumps(raw1), encoding="utf-8")
    (tmp_path / "traj_file_2.json").write_text(json.dumps(raw2), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 1

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 1
    assert audit["rejected_count"] == 1
    assert "duplicate_trajectory_id" in audit["rejection_reasons"]


def test_case_14_duplicate_candidate_id_deduplicated(tmp_path):
    """Case 14: Duplicate candidate_id is ingested only once."""
    raw1 = _build_valid_raw_trajectory(traj_id="traj_alpha", cand_id="cand_shared")
    raw2 = _build_valid_raw_trajectory(traj_id="traj_beta", cand_id="cand_shared")

    (tmp_path / "traj_file_alpha.json").write_text(json.dumps(raw1), encoding="utf-8")
    (tmp_path / "traj_file_beta.json").write_text(json.dumps(raw2), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 1

    audit = audit_trajectory_storage(str(tmp_path))
    assert audit["loader_eligible_count"] == 1
    assert audit["rejected_count"] == 1
    assert "duplicate_candidate_id" in audit["rejection_reasons"]


def test_case_15_audit_eligibility_matches_loader_eligibility(tmp_path):
    """Case 15: Audit eligibility strictly matches real production loader eligibility."""
    # Write a diverse mixture of records
    # 1. Valid production
    (tmp_path / "traj_valid_1.json").write_text(json.dumps(_build_valid_raw_trajectory(traj_id="t1", cand_id="c1")), encoding="utf-8")
    (tmp_path / "traj_valid_2.json").write_text(json.dumps(_build_valid_raw_trajectory(traj_id="t2", cand_id="c2")), encoding="utf-8")
    # 2. Synthetic control
    (tmp_path / "traj_synth.json").write_text(json.dumps(_build_valid_raw_trajectory(traj_id="t3", cand_id="c3", dataset_partition="synthetic_control", is_synthetic=True, trainable=False)), encoding="utf-8")
    # 3. External text only
    (tmp_path / "traj_ext.json").write_text(json.dumps(_build_valid_raw_trajectory(traj_id="t4", cand_id="c4", token_provenance="external_text_only")), encoding="utf-8")
    # 4. Infra error
    (tmp_path / "traj_infra.json").write_text(json.dumps(_build_valid_raw_trajectory(traj_id="t5", cand_id="c5", category="INFRA_ERROR", reward=0.0, trainable=False)), encoding="utf-8")
    # 5. Duplicate of t1
    (tmp_path / "traj_dup.json").write_text(json.dumps(_build_valid_raw_trajectory(traj_id="t1", cand_id="c1")), encoding="utf-8")

    loaded = load_production_trajectories(str(tmp_path))
    audit = audit_trajectory_storage(str(tmp_path))

    assert len(loaded) == 2
    assert audit["loader_eligible_count"] == 2
    assert audit["production_eligible_for_grpo"] == 2
    assert audit["rejected_count"] == 4

    loaded_ids = {r["trajectory_id"] for r in loaded}
    audit_eligible_ids = {r["trajectory_id"] for r in audit["file_records"] if r["is_eligible"]}
    assert loaded_ids == audit_eligible_ids == {"t1", "t2"}


def test_case_16_exact_token_eligibility_matches_strict_loader(tmp_path):
    """Case 16: Exact-token eligibility matches result of strict production loader."""
    # File A: model_generate + valid token IDs
    (tmp_path / "traj_model.json").write_text(json.dumps(_build_valid_raw_trajectory(traj_id="t_model", cand_id="c_model")), encoding="utf-8")
    # File B: external_text_only + valid token IDs
    (tmp_path / "traj_ext.json").write_text(json.dumps(_build_valid_raw_trajectory(traj_id="t_ext", cand_id="c_ext", token_provenance="external_text_only")), encoding="utf-8")

    strict_loaded = load_production_trajectories(str(tmp_path))
    legacy_loaded = legacy_load_trajectories_for_inspection(str(tmp_path))
    audit = audit_trajectory_storage(str(tmp_path))

    assert len(strict_loaded) == 1
    assert strict_loaded[0]["trajectory_id"] == "t_model"
    # Legacy loader allows non-exact tokens for inspection
    assert len(legacy_loaded) == 2
    # Exact token count in audit matches strict loader exactly
    assert audit["exact_token_eligible_count"] == len(strict_loaded) == 1


def test_case_17_investigate_and_resolve_historical_3_vs_6_discrepancy(tmp_path):
    """
    Case 17: Reproduces and confirms resolution of the previous Modal audit discrepancy:
      total_files = 22
      valid_schema_count = 7
      malformed_count = 15
      production = 3
      production_eligible_for_grpo = 6 (OLD BUGGY AUDIT) -> 3 (NEW HARDENED AUDIT)
    """
    # 1. Create 15 malformed files
    for i in range(15):
        (tmp_path / f"traj_malformed_{i:02d}.json").write_text(f"INVALID JSON SYNTAX {i}", encoding="utf-8")

    # 2. Create 3 real production files with exact token lineage
    for i in range(3):
        raw_prod = _build_valid_raw_trajectory(
            traj_id=f"traj_prod_{i}",
            cand_id=f"cand_prod_{i}",
            dataset_partition="production",
            is_synthetic=False,
            trainable=True,
            is_finalized=True,
            token_provenance="model_generate",
            generated_token_ids=[100 + i, 200 + i]
        )
        (tmp_path / f"traj_real_prod_{i:02d}.json").write_text(json.dumps(raw_prod), encoding="utf-8")

    # 3. Create 1 synthetic control file
    raw_synth = _build_valid_raw_trajectory(
        traj_id="traj_synth_01",
        cand_id="cand_synth_01",
        dataset_partition="synthetic_control",
        is_synthetic=True,
        trainable=False,
        token_provenance="synthetic"
    )
    (tmp_path / "traj_synthetic_01.json").write_text(json.dumps(raw_synth), encoding="utf-8")

    # 4. Create 3 legacy files (valid schema under old defaults, but NO provenance fields in raw JSON)
    for i in range(3):
        raw_legacy = {
            "trajectory_id": f"traj_legacy_{i}",
            "candidate_id": f"cand_legacy_{i}",
            "run_id": f"run_legacy_{i}",
            "target_name": "Vault",
            "target_code": "contract Vault {}",
            "prompt_hash": f"hash_legacy_{i}",
            "hypothesis": {"vulnerability_type": "Reentrancy", "reasoning_trace": "", "attack_vector": ""},
            "generated_exploit": "contract Exploit {}",
            "reward": -0.25,
            "category": "RUNTIME_REVERT",
            "is_verified": False,
            "reproduced": False,
            "feedback_trace": "legacy feedback"
            # Provenance fields completely missing in raw JSON!
        }
        (tmp_path / f"traj_legacy_{i:02d}.json").write_text(json.dumps(raw_legacy), encoding="utf-8")

    # Total files must be exactly 22
    files = list(tmp_path.glob("traj_*.json"))
    assert len(files) == 22

    # A. Execute hardened Round 5.4 audit
    audit = audit_trajectory_storage(str(tmp_path))

    assert audit["total_files"] == 22
    assert audit["by_partition"]["production"] == 3
    assert audit["by_partition"]["synthetic_control"] == 1
    assert audit["by_partition"]["missing_or_other"] == 18  # 15 malformed + 3 legacy

    # Under new hardened logic:
    # Production eligible count CANNOT exceed raw production count!
    assert audit["loader_eligible_count"] == 3
    assert audit["production_eligible_for_grpo"] == 3
    assert audit["production_eligible_for_grpo"] <= audit["by_partition"]["production"]
    assert audit["exact_token_eligible_count"] == 3
    assert audit["rejected_count"] == 19  # 15 malformed + 1 synthetic + 3 legacy missing provenance

    # B. Strict production loader also yields exactly 3
    loaded = load_production_trajectories(str(tmp_path))
    assert len(loaded) == 3
    loaded_ids = {r["trajectory_id"] for r in loaded}
    assert loaded_ids == {"traj_prod_0", "traj_prod_1", "traj_prod_2"}
