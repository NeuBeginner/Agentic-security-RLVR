import json
from pathlib import Path
import pytest
from benchmarks.benchmark_runner import AegisBenchmarkSuite, BASELINES


def test_benchmark_dataset_integrity():
    data = json.loads(Path("benchmarks/benchmark_dataset.json").read_text(encoding="utf-8"))
    assert data["vulnerable_targets_count"] >= 12
    assert len(data["classes"]) >= 12
    assert data["synthetic_controls_count"] >= 4
    for cls in data["classes"]:
        for target in cls["targets"]:
            assert target["is_vulnerable"] is True
            assert Path(target["source_file"]).exists()
            assert Path(target["harness_file"]).exists()
    for control in data["synthetic_controls"]:
        assert control["is_vulnerable"] is False
        assert Path(control["source_file"]).exists()


def test_default_benchmark_does_not_invent_metrics():
    report = AegisBenchmarkSuite().run_benchmark(persist=False)
    assert report["overall_status"] == "NOT_RUN"
    assert report["metrics_are_empirical"] is False
    assert report["total_targets"] == 16
    assert set(report["baselines"]) == set(BASELINES)
    for baseline in report["baselines"].values():
        assert baseline["status"] == "NOT_IMPLEMENTED"
        assert baseline["metrics"] is None


def test_adapter_outputs_are_aggregated_into_metrics():
    suite, calls = AegisBenchmarkSuite(), []
    def fixture_adapter(target):
        calls.append(target["contract_id"])
        vulnerable = target["is_vulnerable"]
        return {
            "detected": vulnerable,
            "candidates_generated": 1 if vulnerable else 0,
            "verified_breaches": 1 if vulnerable else 0,
            "replayed_breaches": 1 if vulnerable else 0,
            "duration_seconds": 0.25, "cost_usd": 0.01,
            "verification_evidence": {"test_fixture": True} if vulnerable else None,
            "replay_evidence": {"test_fixture": True} if vulnerable else None,
        }
    suite.adapters = {"baseline_5": fixture_adapter}
    report = suite.run_benchmark(persist=False)
    assert len(calls) == report["total_targets"] == 16
    assert report["overall_status"] == "PARTIAL"
    metrics = report["baselines"]["baseline_5"]
    assert metrics["precision"] == metrics["recall"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["replay_reproducibility_rate"] == 1.0


def test_benchmark_refuses_unproven_verified_breach():
    suite = AegisBenchmarkSuite()
    def invalid_adapter(target):
        return {"detected": True, "candidates_generated": 1, "verified_breaches": 1}
    suite.adapters = {"baseline_5": invalid_adapter}
    with pytest.raises(ValueError, match="verification_evidence"):
        suite.run_benchmark(persist=False)
