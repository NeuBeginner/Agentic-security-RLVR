"""
tests/test_real_benchmark_execution.py

Unit and integration tests for real Aegis-RLVR benchmark execution:
1. Zero ground-truth leakage into baseline adapters.
2. Honest fail-closed handling (UNAVAILABLE status, no fake metrics) when tools/credentials are missing.
3. Baseline 3 (unverified PoC) never produces verified breaches.
4. Dynamic candidate counts derived from actual output, not hardcoded constants.
5. Full Aegis-RLVR strictly requires trusted harness in production allowlist and EVM Oracle verification.
6. Machine-readable artifacts with full provenance persisted per-target and per-baseline.
7. Provider detection and routing alignment (no false availability when provider differs).
8. Slither non-zero exit or unparseable JSON classified as FAILED, not SUCCESS with 0 findings.
9. Evaluator mixed SUCCESS + FAILED targets is marked INCOMPLETE with strictly None metrics.
10. Unmeasured costs report None, never fabricating constant dollar figures.
"""

import json
import tempfile
import subprocess
from pathlib import Path
import pytest

from benchmarks.protocol import (
    BenchmarkDataset,
    TargetSpecification,
    GroundTruth,
    TargetExecutionArtifact,
    BaselineEvaluationResult,
    ExecutionStatus,
)
from benchmarks.evaluator import evaluate_baseline_run
from benchmarks.adapters import (
    SlitherBaselineAdapter,
    LLMAuditorBaselineAdapter,
    LLMUnverifiedPoCBaselineAdapter,
    LLMNaiveFoundryBaselineAdapter,
    FullAegisRLVRBaselineAdapter,
    SyntheticSmokeAdapter,
    check_llm_provider_availability,
)
from benchmarks.benchmark_runner import AegisBenchmarkSuite


def test_ground_truth_leakage_prevented():
    """Verify that TargetSpecification physically excludes ground-truth fields."""
    dataset = BenchmarkDataset()
    public_targets = dataset.get_public_targets()
    ground_truth = dataset.get_ground_truth()

    assert len(public_targets) >= 16
    assert len(ground_truth) >= 16

    for target in public_targets:
        assert isinstance(target, TargetSpecification)
        assert not hasattr(target, "is_vulnerable")
        assert not hasattr(target, "ground_truth_invariant")
        assert not hasattr(target, "vulnerable_functions")

        # Ground truth exists separately
        gt = ground_truth.get(target.contract_id)
        assert gt is not None
        assert isinstance(gt, GroundTruth)
        assert isinstance(gt.is_vulnerable, bool)


def test_missing_tool_returns_unavailable_not_zero_or_fake_metrics():
    """When a baseline tool is missing, status must be UNAVAILABLE and metrics must be None."""
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    # Adapter with guaranteed missing tool
    class MissingToolAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return False, "Synthetic test: tool missing"

    adapter = MissingToolAdapter()
    artifact = adapter.execute_target(target)

    assert artifact.status == ExecutionStatus.UNAVAILABLE
    assert artifact.unavailable_reason == "Synthetic test: tool missing"
    assert artifact.detected is False

    # Evaluation with UNAVAILABLE artifact must yield None for precision/recall/F1
    eval_res = evaluate_baseline_run(
        baseline_id="missing_tool",
        baseline_name="Missing Tool Baseline",
        artifacts=[artifact],
        ground_truth_map=dataset.get_ground_truth(),
    )

    assert eval_res.status == ExecutionStatus.UNAVAILABLE
    assert eval_res.precision is None
    assert eval_res.recall is None
    assert eval_res.f1_score is None
    assert eval_res.false_positive_rate is None
    assert eval_res.false_negative_rate is None
    assert eval_res.exploit_success_rate is None
    assert "Synthetic test: tool missing" in (eval_res.status_reason or "")


def test_unverified_poc_cannot_have_verified_breaches():
    """Baseline 3 generates PoC candidates but never verifies breaches in EVM."""
    mock_client = lambda prompt: "contract ExploitModule { function runExploit() public {} }"
    adapter = LLMUnverifiedPoCBaselineAdapter(client_override=mock_client)

    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    artifact = adapter.execute_target(target)
    assert artifact.status == ExecutionStatus.SUCCESS
    assert artifact.detected is True
    assert artifact.candidates_generated >= 1
    # Absolute invariant: Unverified PoC cannot claim verified or replayed breaches
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0


def test_candidates_count_is_dynamic_not_constant():
    """Candidate count must reflect actual generator output, not hardcoded numbers."""
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    # 1. Output without exploit code
    no_code_client = lambda prompt: "I cannot find any vulnerabilities in this contract."
    adapter_empty = LLMUnverifiedPoCBaselineAdapter(client_override=no_code_client)
    artifact_empty = adapter_empty.execute_target(target)
    assert artifact_empty.candidates_generated == 0
    assert artifact_empty.detected is False

    # 2. Output with exploit code
    code_client = lambda prompt: "```solidity\ncontract ExploitModule { function runExploit() external {} }\n```"
    adapter_code = LLMUnverifiedPoCBaselineAdapter(client_override=code_client)
    artifact_code = adapter_code.execute_target(target)
    assert artifact_code.candidates_generated == 1
    assert artifact_code.detected is True


def test_full_aegis_rlvr_rejects_non_allowlisted_harness():
    """Full Aegis-RLVR must report UNAVAILABLE for targets without trusted harness in allowlist."""
    dataset = BenchmarkDataset()
    targets = dataset.get_public_targets()

    # Find a target not in production allowlist (e.g. AuctionDoS / DOS-01)
    non_allowlisted = [t for t in targets if t.target_name not in ("Vault", "ERC4626Vault")][0]

    adapter = FullAegisRLVRBaselineAdapter()
    artifact = adapter.execute_target(non_allowlisted)

    assert artifact.status == ExecutionStatus.UNAVAILABLE
    assert "not in production trusted harness allowlist" in artifact.unavailable_reason
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0


def test_raw_artifacts_persisted_with_provenance():
    """Verify that execution writes individual JSON artifacts per target with full provenance."""
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        report = suite.run_benchmark(mode="smoke", save_results=True)

        assert report["is_synthetic_smoke"] is True
        artifacts_dir = Path(tmpdir) / list(Path(tmpdir).glob("run_*"))[0].name
        assert artifacts_dir.exists()

        # Check directory structure
        for b_id in ["baseline_1", "baseline_2", "baseline_3", "baseline_4", "baseline_5"]:
            b_dir = artifacts_dir / b_id
            assert b_dir.exists(), f"Directory for {b_id} must exist"
            target_files = list(b_dir.glob("*.json"))
            assert len(target_files) >= 16

            # Verify contents of an artifact file
            with open(target_files[0], "r", encoding="utf-8") as f:
                data = json.load(f)
                assert "baseline_id" in data
                assert "target_id" in data
                assert "status" in data
                assert "tool_metadata" in data
                assert "raw_output" in data
                assert "logs" in data
                assert "duration_seconds" in data


def test_evaluator_confusion_matrix_accuracy():
    """Test mathematical accuracy of post-run evaluator on known artifact fixtures."""
    ground_truth = {
        "V1": GroundTruth(contract_id="V1", is_vulnerable=True),
        "V2": GroundTruth(contract_id="V2", is_vulnerable=True),
        "V3": GroundTruth(contract_id="V3", is_vulnerable=True),
        "S1": GroundTruth(contract_id="S1", is_vulnerable=False),
        "S2": GroundTruth(contract_id="S2", is_vulnerable=False),
    }

    artifacts = [
        TargetExecutionArtifact(
            baseline_id="b_test", target_id="V1", target_name="V1",
            status=ExecutionStatus.SUCCESS, detected=True, candidates_generated=2, verified_breaches=1, replayed_breaches=1,
            cost_usd=0.01
        ),
        TargetExecutionArtifact(
            baseline_id="b_test", target_id="V2", target_name="V2",
            status=ExecutionStatus.SUCCESS, detected=True, candidates_generated=3, verified_breaches=1, replayed_breaches=1,
            cost_usd=0.01
        ),
        TargetExecutionArtifact(
            baseline_id="b_test", target_id="V3", target_name="V3",
            status=ExecutionStatus.SUCCESS, detected=False, candidates_generated=1, verified_breaches=0, replayed_breaches=0,
            cost_usd=0.01
        ),
        TargetExecutionArtifact(
            baseline_id="b_test", target_id="S1", target_name="S1",
            status=ExecutionStatus.SUCCESS, detected=True, candidates_generated=2, verified_breaches=0, replayed_breaches=0,
            cost_usd=0.01
        ),
        TargetExecutionArtifact(
            baseline_id="b_test", target_id="S2", target_name="S2",
            status=ExecutionStatus.SUCCESS, detected=False, candidates_generated=0, verified_breaches=0, replayed_breaches=0,
            cost_usd=0.01
        ),
    ]

    res = evaluate_baseline_run("b_test", "Test Baseline", artifacts, ground_truth)

    assert res.status == ExecutionStatus.SUCCESS
    assert res.true_positives == 2
    assert res.false_positives == 1
    assert res.true_negatives == 1
    assert res.false_negatives == 1

    # Precision = 2 / (2 + 1) = 0.6667
    assert res.precision == round(2 / 3, 4)
    # Recall = 2 / (2 + 1) = 0.6667
    assert res.recall == round(2 / 3, 4)
    # F1 = 2 * (0.6667 * 0.6667) / (0.6667 + 0.6667) = 0.6667
    assert res.f1_score == round(2 / 3, 4)
    # FPR = 1 / (1 + 1) = 0.5
    assert res.false_positive_rate == 0.5
    # FNR = 1 / (2 + 1) = 0.3333
    assert res.false_negative_rate == round(1 / 3, 4)
    # Exploit success rate = 2 verified / 8 candidates = 0.25
    assert res.exploit_success_rate == 0.25
    # Replay rate = 2 replayed / 2 verified = 1.0
    assert res.replay_reproducibility_rate == 1.0
    assert res.estimated_cost_usd_per_target == 0.01


def test_provider_detection_and_routing(monkeypatch):
    """Test that provider configuration strictly aligns with credential checks."""
    # Case A: Only OPENAI_API_KEY in env, but adapter configured for Gemini
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-mock-key")

    gemini_adapter = LLMAuditorBaselineAdapter(provider="gemini")
    avail, reason = gemini_adapter.check_availability()
    assert avail is False
    assert "Gemini API credentials" in reason

    # Case B: Adapter configured for OpenAI with OPENAI_API_KEY
    openai_adapter = LLMAuditorBaselineAdapter(provider="openai")
    avail_oai, _ = openai_adapter.check_availability()
    assert avail_oai is True

    # Case C: Unsupported provider
    unknown_adapter = LLMAuditorBaselineAdapter(provider="anthropic")
    avail_unk, reason_unk = unknown_adapter.check_availability()
    assert avail_unk is False
    assert "Unsupported LLM provider" in reason_unk


def test_slither_non_zero_exit_or_missing_json_marked_failed(monkeypatch):
    """If Slither exits non-zero without valid JSON, it must be marked FAILED, not SUCCESS with 0 findings."""
    class FailingSlitherAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return True, None
        def get_slither_version(self):
            return "0.10.4"

    adapter = FailingSlitherAdapter()
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    # Mock subprocess.run to simulate compilation failure
    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="",
            stderr="Error: Source file requires different compiler version\nCompilation failed"
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.FAILED
    assert "Slither failed" in (artifact.unavailable_reason or "")
    assert artifact.detected is False
    assert artifact.cost_usd is None
    assert artifact.raw_output["stderr"] != ""


def test_evaluator_mixed_success_and_failed_is_incomplete_and_unscorable():
    """Any baseline with failed/unavailable targets must be INCOMPLETE and non-scorable."""
    ground_truth = {
        "T1": GroundTruth(contract_id="T1", is_vulnerable=True),
        "T2": GroundTruth(contract_id="T2", is_vulnerable=True),
        "T3": GroundTruth(contract_id="T3", is_vulnerable=False),
    }

    # 2 succeeded, 1 failed
    artifacts = [
        TargetExecutionArtifact(
            baseline_id="b_test", target_id="T1", target_name="T1",
            status=ExecutionStatus.SUCCESS, detected=True
        ),
        TargetExecutionArtifact(
            baseline_id="b_test", target_id="T2", target_name="T2",
            status=ExecutionStatus.FAILED, unavailable_reason="Compilation error", detected=False
        ),
        TargetExecutionArtifact(
            baseline_id="b_test", target_id="T3", target_name="T3",
            status=ExecutionStatus.SUCCESS, detected=False
        ),
    ]

    res = evaluate_baseline_run("b_test", "Mixed Run", artifacts, ground_truth)

    assert res.status == ExecutionStatus.INCOMPLETE
    assert "1 failed" in res.status_reason
    assert res.completed_targets == 2
    assert res.total_targets == 3
    # Absolute invariant: failed run is NEVER counted as detected=False
    assert res.precision is None
    assert res.recall is None
    assert res.f1_score is None
    assert res.true_positives is None
    assert res.false_negatives is None


def test_cost_usd_none_when_unmeasured():
    """Unmeasured costs must report None, never fake hardcoded numbers."""
    adapter = SyntheticSmokeAdapter("baseline_2", "LLM Auditor")
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    artifact = adapter.execute_target(target)
    assert artifact.cost_usd is None

    eval_res = evaluate_baseline_run(
        "baseline_2", "LLM Auditor", [artifact], dataset.get_ground_truth()
    )
    assert eval_res.estimated_cost_usd_per_target is None
