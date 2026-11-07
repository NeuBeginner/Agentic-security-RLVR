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


def test_smoke_output_is_explicitly_synthetic_and_stable():
    """Smoke fixtures validate plumbing only; they are not evidence of model performance."""
    suite = AegisBenchmarkSuite()
    first = suite.run_benchmark(mode="smoke", save_results=False)
    second = suite.run_benchmark(mode="smoke", save_results=False)
    assert first["is_synthetic_smoke"] is True
    assert first["execution_mode"] == "SYNTHETIC_SMOKE_TEST"
    assert first["baselines"]["baseline_5"]["details"] == second["baselines"]["baseline_5"]["details"]

def test_benchmark_separates_smoke_and_real_experiments():
    """Benchmark runner must explicitly distinguish between synthetic smoke tests and real experiments."""
    suite = AegisBenchmarkSuite()
    smoke_report = suite.run_benchmark(mode="smoke", save_results=False)
    assert smoke_report["is_synthetic_smoke"] is True
    assert smoke_report["execution_mode"] == "SYNTHETIC_SMOKE_TEST"

    # Real mode must fail closed until each baseline has a real executable adapter.
    with pytest.raises(NotImplementedError, match="executable adapters"):
        suite.run_benchmark(mode="real", model_id="eval-model-v1", save_results=False)


def test_benchmark_ground_truth_and_metrics_consistency():
    """Validates that precision, recall, F1, FPR, and FNR strictly follow ground truth math."""
    metrics = BaselineMetrics(baseline_id="test", baseline_name="Test Baseline")
    metrics.true_positives = 10
    metrics.false_positives = 0
    metrics.true_negatives = 4
    metrics.false_negatives = 2
    metrics.calculate_derived_metrics(total_candidates=20, total_verified=10, total_replayed=10)

    assert metrics.precision == 1.0
    assert metrics.recall == round(10 / 12, 4)
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == round(2 / 12, 4)
    assert metrics.exploit_success_rate == 0.5
    assert metrics.replay_reproducibility_rate == 1.0
