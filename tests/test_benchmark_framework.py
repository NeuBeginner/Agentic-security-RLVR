"""
Tests for Aegis-RLVR Benchmark Suite and Evaluation Methodology.
Verifies dataset integrity, coverage of 12 vulnerability classes,
presence of synthetic controls, and comparative baseline evaluation.
"""

import json
from pathlib import Path
import pytest
from benchmarks.benchmark_runner import AegisBenchmarkSuite, BaselineMetrics


def test_benchmark_dataset_integrity():
    dataset_path = Path("benchmarks/benchmark_dataset.json")
    assert dataset_path.exists(), "Benchmark dataset file must exist"

    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "benchmark_version" in data
    assert data["vulnerable_targets_count"] >= 12
    assert len(data["classes"]) >= 12
    assert data["synthetic_controls_count"] >= 4

    # Verify every target has existing source files
    for c in data["classes"]:
        for t in c["targets"]:
            assert "contract_id" in t
            assert "target_name" in t
            assert t["is_vulnerable"] is True
            assert "ground_truth_invariant" in t
            
            src = Path(t["source_file"])
            harness = Path(t["harness_file"])
            assert src.exists(), f"Source file {src} must exist"
            assert harness.exists(), f"Harness file {harness} must exist"

    # Verify synthetic controls exist and are marked safe
    for ctrl in data["synthetic_controls"]:
        assert ctrl["is_vulnerable"] is False
        assert ctrl["ground_truth_invariant"] == "NONE"
        src = Path(ctrl["source_file"])
        assert src.exists(), f"Control source file {src} must exist"


def test_benchmark_runner_executes_all_baselines():
    suite = AegisBenchmarkSuite()
    report = suite.run_benchmark()

    assert report["total_targets_evaluated"] >= 16
    assert report["vulnerable_targets"] >= 12
    assert report["synthetic_controls"] >= 4

    baselines = report["baselines"]
    expected_baselines = [
        "baseline_1", "baseline_2", "baseline_3", "baseline_4", "baseline_5"
    ]
    for b_id in expected_baselines:
        assert b_id in baselines
        b_data = baselines[b_id]
        assert "precision" in b_data
        assert "recall" in b_data
        assert "f1_score" in b_data
        assert "false_positive_rate" in b_data
        assert "false_negative_rate" in b_data
        assert "exploit_success_rate" in b_data
        assert "verified_finding_rate" in b_data
        assert "replay_reproducibility_rate" in b_data


def test_full_aegis_rlvr_outperforms_naive_and_static_baselines():
    suite = AegisBenchmarkSuite()
    report = suite.run_benchmark()
    baselines = report["baselines"]

    b1_slither = baselines["baseline_1"]
    b2_auditor = baselines["baseline_2"]
    b4_naive = baselines["baseline_4"]
    b5_aegis = baselines["baseline_5"]

    # Aegis-RLVR must maintain 0% False Positive Rate on synthetic controls
    assert b5_aegis["false_positive_rate"] == 0.0
    # Aegis-RLVR must achieve highest F1 score
    assert b5_aegis["f1_score"] > b1_slither["f1_score"]
    assert b5_aegis["f1_score"] > b4_naive["f1_score"]
    # Replay reproducibility on confirmed exploits must be 1.0 (100%)
    assert b5_aegis["replay_reproducibility_rate"] == 1.0
    # Verified finding rate must be > 0.8
    assert b5_aegis["verified_finding_rate"] >= 0.8
