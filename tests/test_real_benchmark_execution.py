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
import hashlib
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
    BaselineAdapter,
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


# =============================================================================
# Issue #9 Regression & Contract Tests: Slither Adapter Hardening
# =============================================================================

def test_slither_nonzero_exit_with_valid_json_marked_failed(monkeypatch):
    """
    P0 Requirement: Non-zero exit code MUST be classified as FAILED even if
    valid JSON was produced during partial execution. Never mark SUCCESS.
    """
    class MockSlitherAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return True, None
        def get_slither_version(self):
            return "0.10.4"

    adapter = MockSlitherAdapter()
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    valid_json_payload = {
        "success": True,
        "results": {
            "detectors": [
                {"check": "reentrancy-eth", "impact": "High", "confidence": "High", "description": "Reentrancy detected"}
            ]
        }
    }

    def mock_subprocess_run(cmd, *args, **kwargs):
        # Write valid JSON file even though process exited with returncode 1
        json_path = cmd[3]  # --json <path>
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(valid_json_payload, f)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="Analysis completed partially but process exited with error",
            stderr="Error: Fatal AST traversal error after detector phase"
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.FAILED
    assert "Slither failed (exit code 1)" in (artifact.unavailable_reason or "")
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0
    assert artifact.tool_metadata["stdout_sha256"] != ""
    assert artifact.tool_metadata["stderr_sha256"] != ""
    assert artifact.tool_metadata["exit_code"] == 1


def test_slither_nonzero_exit_with_malformed_json_marked_failed(monkeypatch):
    """P0 Requirement: Non-zero exit with malformed JSON output must be FAILED."""
    class MockSlitherAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return True, None
        def get_slither_version(self):
            return "0.10.4"

    adapter = MockSlitherAdapter()
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    def mock_subprocess_run(cmd, *args, **kwargs):
        json_path = cmd[3]
        with open(json_path, "w", encoding="utf-8") as f:
            f.write("{ invalid json syntax ...")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=2,
            stdout="",
            stderr="Fatal syntax crash"
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.FAILED
    assert "exit code 2" in (artifact.unavailable_reason or "")
    assert artifact.detected is False


def test_slither_zero_exit_with_malformed_json_marked_failed(monkeypatch):
    """P0 Requirement: Zero exit code with malformed JSON must be FAILED, never empty findings."""
    class MockSlitherAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return True, None
        def get_slither_version(self):
            return "0.10.4"

    adapter = MockSlitherAdapter()
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    def mock_subprocess_run(cmd, *args, **kwargs):
        json_path = cmd[3]
        with open(json_path, "w", encoding="utf-8") as f:
            f.write("{ corrupt json ...")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="Finished with returncode 0",
            stderr=""
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.FAILED
    assert "Failed to parse Slither JSON output" in (artifact.unavailable_reason or "")
    assert artifact.detected is False


def test_slither_zero_exit_with_missing_expected_fields_marked_failed(monkeypatch):
    """P0 Requirement: Zero exit with missing results/detectors must be FAILED."""
    class MockSlitherAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return True, None
        def get_slither_version(self):
            return "0.10.4"

    adapter = MockSlitherAdapter()
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    def mock_subprocess_run(cmd, *args, **kwargs):
        json_path = cmd[3]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"success": True, "results": {}}, f)  # missing detectors list
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.FAILED
    assert "missing 'results.detectors' list" in (artifact.unavailable_reason or "")


def test_slither_zero_exit_with_valid_empty_findings_is_success_not_detected(monkeypatch):
    """P0 Requirement: Zero exit code with valid empty detectors list is SUCCESS with detected=False."""
    class MockSlitherAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return True, None
        def get_slither_version(self):
            return "0.10.4"

    adapter = MockSlitherAdapter()
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    def mock_subprocess_run(cmd, *args, **kwargs):
        json_path = cmd[3]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"success": True, "results": {"detectors": []}}, f)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="Clean analysis, 0 detectors triggered",
            stderr=""
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.SUCCESS
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.tool_metadata["detectors_count"] == 0
    assert artifact.tool_metadata["stdout_sha256"] != ""
    assert artifact.tool_metadata["stderr_sha256"] != ""


def test_slither_zero_exit_with_valid_findings_is_success_and_detected(monkeypatch):
    """P0 Requirement: Zero exit code with valid High/Medium detectors is SUCCESS with detected=True."""
    class MockSlitherAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return True, None
        def get_slither_version(self):
            return "0.10.4"

    adapter = MockSlitherAdapter()
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    def mock_subprocess_run(cmd, *args, **kwargs):
        json_path = cmd[3]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "success": True,
                "results": {
                    "detectors": [
                        {"check": "reentrancy-eth", "impact": "High", "confidence": "High", "description": "Reentrancy flaw"},
                        {"check": "uninitialized-state", "impact": "Medium", "confidence": "Medium", "description": "Uninitialized"},
                    ]
                }
            }, f)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="Found 2 issues",
            stderr=""
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.SUCCESS
    assert artifact.detected is True
    assert artifact.verified_breaches == 0
    assert artifact.tool_metadata["detectors_count"] == 2


# =============================================================================
# Issue #9 Regression & Contract Tests: Foundry Naive Baseline Separation
# =============================================================================

def test_foundry_naive_zero_exit_without_executed_tests_is_not_verified(monkeypatch):
    """
    P0 Requirement: Exit code 0 without any actually executed tests (0 tests run)
    must NOT count as test pass or verified breach.
    """
    adapter = LLMNaiveFoundryBaselineAdapter(
        client_override=lambda prompt: "contract ExploitModule { }"
    )
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    monkeypatch.setattr(adapter, "check_availability", lambda: (True, None))
    monkeypatch.setattr(adapter, "get_forge_version", lambda: "forge 0.2.0")

    # Mock subprocess returning 0 with empty test suite (0 tests run)
    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps({"test/ExploitModule.sol:ExploitModule": {"test_results": {}}}),
            stderr=""
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.FAILED
    assert "0 test cases" in (artifact.unavailable_reason or "")
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0
    assert artifact.tool_metadata["test_pass"] is False
    assert artifact.tool_metadata["naive_signal"] is False


def test_foundry_naive_nonzero_exit_or_compilation_error_is_not_verified(monkeypatch):
    """
    P0 Requirement: Non-zero exit code or compilation error must NOT be verified.
    """
    adapter = LLMNaiveFoundryBaselineAdapter(
        client_override=lambda prompt: "contract BrokenSyntax { {"
    )
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    monkeypatch.setattr(adapter, "check_availability", lambda: (True, None))
    monkeypatch.setattr(adapter, "get_forge_version", lambda: "forge 0.2.0")

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="Compiler run failed:\nParserError: Expected identifier but got '{'",
            stderr="Error during compilation"
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.FAILED
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0
    assert artifact.tool_metadata["test_pass"] is False
    assert artifact.tool_metadata["naive_signal"] is False


def test_foundry_naive_passing_test_is_naive_signal_only_never_verified_breach(monkeypatch):
    """
    P0 Requirement: A passing test in naive baseline indicates test_pass / naive signal,
    but MUST NEVER be classified as a verified invariant breach (verified_breaches == 0).
    """
    adapter = LLMNaiveFoundryBaselineAdapter(
        client_override=lambda prompt: "contract ExploitModule { function testExploit() external { } }"
    )
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]

    monkeypatch.setattr(adapter, "check_availability", lambda: (True, None))
    monkeypatch.setattr(adapter, "get_forge_version", lambda: "forge 0.2.0")

    forge_json = {
        "test/ExploitModule.sol:ExploitModule": {
            "test_results": {
                "testExploit()": {
                    "status": "Success",
                    "reason": None,
                    "counterexample": None,
                    "decoded_logs": []
                }
            }
        }
    }

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps(forge_json),
            stderr=""
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    artifact = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert artifact.status == ExecutionStatus.SUCCESS
    assert artifact.detected is True  # Naive baseline detection heuristic
    # STRICT P0 INVARIANT: Must NEVER count as a verified breach or replayed breach
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0
    assert artifact.tool_metadata["test_pass"] is True
    assert artifact.tool_metadata["naive_signal"] is True
    assert artifact.tool_metadata["total_tests_run"] == 1
    assert artifact.tool_metadata["passed_tests"] == 1
    assert artifact.tool_metadata["forge_version"] == "forge 0.2.0"
    assert artifact.tool_metadata["stdout_sha256"] != ""
    assert artifact.tool_metadata["candidate_code_sha256"] != ""


# =============================================================================
# Issue #9 Reproducibility Manifest & Environment Provenance Tests
# =============================================================================

def test_run_reproducibility_manifest_schema_and_portable_relative_paths():
    """
    P1 Requirement: Every run produces a reproducibility manifest containing:
    - git commit sha, branch, dirty status;
    - environment versions (python, slither, forge, solc, modal, packages, providers);
    - dataset version and sha256;
    - adapter structured argv, commands, effective config hashes, resource budgets,
      per-target provenance, and artifact files with SHA-256 and byte sizes;
    - strictly repository-relative portable paths (no developer absolute paths).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(mode="smoke", baselines_to_run=["baseline_1", "baseline_4"], save_results=True)

        assert rep["reproducibility_manifest"] is not None
        manifest_summary = rep["reproducibility_manifest_summary"]

        # Check git metadata
        assert "commit_sha" in manifest_summary["git"]
        assert "is_dirty" in manifest_summary["git"]
        assert "branch" in manifest_summary["git"]

        # Check environment metadata
        env = manifest_summary["environment"]
        assert "python_version" in env
        assert "os_platform" in env
        assert isinstance(env.get("package_versions"), dict)
        assert "pydantic" in env.get("package_versions", {})
        assert "pytest" in env.get("package_versions", {})
        assert isinstance(env.get("provider_configs"), dict)
        assert "gemini" in env.get("provider_configs", {})
        assert "openai" in env.get("provider_configs", {})

        # Check dataset metadata
        ds = manifest_summary["dataset"]
        assert ds["version"] == "1.0.0"
        assert len(ds["dataset_sha256"]) == 64
        assert ds["target_count"] == 16
        assert len(ds["target_ids"]) == 16

        # Check adapter manifests
        adapters_manifest = manifest_summary["adapters"]
        assert "baseline_1" in adapters_manifest
        assert "baseline_4" in adapters_manifest

        b1_man = adapters_manifest["baseline_1"]
        assert b1_man["baseline_id"] == "baseline_1"
        assert b1_man["target_count"] == 16
        assert b1_man["cost_status"] == "unmeasured"
        assert b1_man["cost_usd"] is None
        assert len(b1_man["artifact_files"]) == 16

        # P1 REQUIREMENT: Exact structured argv, effective config hash, and resource budget
        # Adapter-level actual argv/command are strictly None; templates are in planned_argv/command
        assert b1_man["argv"] is None
        assert b1_man["command"] is None
        assert b1_man["planned_argv"] == ["synthetic_smoke_runner", "--baseline", "baseline_1"]
        assert b1_man["planned_command"] == "synthetic_smoke_runner --baseline baseline_1"
        assert len(b1_man["config_hash"]) == 64
        assert b1_man["timeout_sec"] == 5
        assert isinstance(b1_man["resource_budget"], dict)
        assert b1_man["resource_budget"]["mode"] == "synthetic_smoke"

        # P1 REQUIREMENT: Per-target provenance derived directly from execution records
        assert "per_target_provenance" in b1_man
        assert len(b1_man["per_target_provenance"]) == 16
        for tid, t_prov in b1_man["per_target_provenance"].items():
            assert "argv" in t_prov
            assert isinstance(t_prov["argv"], list)
            assert t_prov["argv"][:3] == ["synthetic_smoke_runner", "--baseline", "baseline_1"]
            assert t_prov["timeout_sec"] == 5
            assert len(t_prov["effective_config_hash"]) == 64

        # Check that artifact file records have portable relative paths and valid SHA-256
        for art_rec in b1_man["artifact_files"]:
            assert not art_rec["relative_path"].startswith("C:")
            assert not art_rec["relative_path"].startswith("D:")
            assert not art_rec["relative_path"].startswith("/")
            assert art_rec["size_bytes"] > 0
            assert len(art_rec["sha256"]) == 64


def test_manifest_derived_from_actual_execution_records_and_custom_adapter_config():
    """
    P1 Requirement: Proves that the reproducibility manifest dynamically and deterministically
    derives adapter command, structured argv, timeout, and resource budget from the actual
    execution records rather than a static hardcoded descriptor map.
    """
    custom_budget = {"timeout_sec": 42, "max_memory_mb": 4096, "custom_flag": "test_provenance"}
    adapter = SyntheticSmokeAdapter(
        baseline_id="baseline_1",
        baseline_name="Custom Static Analysis Baseline",
        timeout_sec=42,
        resource_budget=custom_budget,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        assert b1_man["timeout_sec"] == 42
        assert b1_man["resource_budget"] == custom_budget
        assert b1_man["config_hash"] == adapter.get_effective_config_hash()
        assert b1_man["argv"] is None
        assert b1_man["command"] is None
        assert b1_man["planned_argv"] == ["synthetic_smoke_runner", "--baseline", "baseline_1"]
        assert b1_man["planned_command"] == "synthetic_smoke_runner --baseline baseline_1"

        # Check that all 16 target records received the custom timeout and budget
        for tid, t_prov in b1_man["per_target_provenance"].items():
            assert t_prov["timeout_sec"] == 42
            assert t_prov["effective_config_hash"] == adapter.get_effective_config_hash()


def test_real_adapter_structured_argv_and_effective_config_hash(monkeypatch):
    """
    P1 Requirement: Proves that Slither and Naive Foundry adapters emit structured argv arrays
    when executed, null argv when unavailable, and deterministic effective_config_hashes,
    timeout_sec, and resource budgets in their per-target artifacts.
    """
    target = TargetSpecification(
        contract_id="TEST-01",
        target_name="Vault",
        source_file="benchmarks/targets/solidity/Vault.sol",
        harness_file="benchmarks/targets/solidity/VaultHarness.t.sol",
    )

    # 1. Slither adapter unavailable state (no binary on path): argv must be None (P1-B)
    slither_adapter = SlitherBaselineAdapter(timeout_sec=35, resource_budget={"timeout_sec": 35, "opt": True})
    slither_unavail_art = slither_adapter.execute_target(target, base_dir=Path(__file__).parent.parent)
    assert slither_unavail_art.status == ExecutionStatus.UNAVAILABLE
    assert slither_unavail_art.argv is None
    assert slither_unavail_art.timeout_sec is None
    assert slither_unavail_art.resource_budget == {}
    assert slither_unavail_art.effective_config_hash is None

    # 2. Slither adapter executed state: argv must be list of tokens passed to subprocess (P1-C)
    monkeypatch.setattr(slither_adapter, "check_availability", lambda: (True, None))
    monkeypatch.setattr(slither_adapter, "get_slither_version", lambda: "0.10.4")

    def mock_slither_run(cmd, *args, **kwargs):
        json_path = cmd[3]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"success": True, "results": {"detectors": []}}, f)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="slither success", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_slither_run)
    slither_exec_art = slither_adapter.execute_target(target, base_dir=Path(__file__).parent.parent)
    assert slither_exec_art.status == ExecutionStatus.SUCCESS
    assert slither_exec_art.argv is not None
    assert isinstance(slither_exec_art.argv, list)
    assert slither_exec_art.argv[0] == "slither"
    assert slither_exec_art.tool_metadata["exit_code"] == 0
    assert slither_exec_art.timeout_sec == 35
    assert slither_exec_art.resource_budget == {"timeout_sec": 35, "opt": True}
    assert len(slither_exec_art.effective_config_hash) == 64

    # 3. Naive Foundry adapter executed state: argv must be forge tokens (P1-C)
    foundry_adapter = LLMNaiveFoundryBaselineAdapter(
        timeout_sec=55,
        resource_budget={"timeout_sec": 55, "offline": True},
        client_override=lambda p: "contract ExploitModule { function runExploit() external {} }",
    )
    monkeypatch.setattr(foundry_adapter, "check_availability", lambda: (True, None))
    monkeypatch.setattr(foundry_adapter, "get_forge_version", lambda: "forge 0.2.0")

    def mock_forge_run(cmd, *args, **kwargs):
        out_json = {"test/ExploitModule.sol:ExploitModule": {"test_results": {"testExploit()": {"status": "Success"}}}}
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=json.dumps(out_json), stderr="")

    monkeypatch.setattr(subprocess, "run", mock_forge_run)
    foundry_art = foundry_adapter.execute_target(target, base_dir=Path(__file__).parent.parent)
    assert foundry_art.status == ExecutionStatus.SUCCESS
    assert foundry_art.argv == ["forge", "test", "--offline", "--json"]
    assert foundry_art.tool_metadata["exit_code"] == 0
    assert foundry_art.timeout_sec == 55
    assert foundry_art.resource_budget == {"timeout_sec": 55, "offline": True}
    assert len(foundry_art.effective_config_hash) == 64


def test_manifest_preserves_integer_zero_exit_code():
    """
    P1-A Requirement: Regression test proving that a successful process exit
    (exit_code: 0) is persisted as integer 0 in the manifest per_target_provenance,
    rather than dropped by truthiness checks.
    """
    adapter = SyntheticSmokeAdapter(
        baseline_id="baseline_1",
        baseline_name="Synthetic Baseline",
        timeout_sec=10,
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        per_target = b1_man["per_target_provenance"]
        assert len(per_target) > 0

        # Check every target has exit_code exactly equal to integer 0
        for tid, t_prov in per_target.items():
            assert "exit_code" in t_prov
            assert t_prov["exit_code"] == 0
            assert isinstance(t_prov["exit_code"], int)
            assert not isinstance(t_prov["exit_code"], bool)


def test_manifest_uninvoked_and_unavailable_targets_have_null_actual_argv_and_command():
    """
    P1-B Requirement: Tests that for targets where no invocation occurred (UNAVAILABLE),
    actual argv and command are null/None, status says UNAVAILABLE, and planned_argv holds
    the adapter's template command separately.
    """
    class UnavailableMockSlitherAdapter(SlitherBaselineAdapter):
        def check_availability(self):
            return False, "Slither toolchain missing on host"

    adapter = UnavailableMockSlitherAdapter(timeout_sec=20)
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        assert b1_man["availability_status"] == "UNAVAILABLE"
        # Adapter level: actual execution evidence is null because no subprocess was run
        assert b1_man["argv"] is None
        assert b1_man["command"] is None
        # Planned template is stored separately
        assert b1_man["planned_argv"] == adapter.get_default_argv()
        assert b1_man["planned_command"] == " ".join(adapter.get_default_argv())

        # Target level: all targets have null actual argv, null command, null exit code, null provenance
        for tid, t_prov in b1_man["per_target_provenance"].items():
            assert t_prov["status"] == "UNAVAILABLE"
            assert t_prov["argv"] is None
            assert t_prov["command"] is None
            assert t_prov["exit_code"] is None
            assert t_prov["timeout_sec"] is None
            assert t_prov["resource_budget"] is None
            assert t_prov["effective_config_hash"] is None
            assert "missing on host" in (t_prov["unavailable_reason"] or "")


def test_manifest_provider_api_calls_have_no_invented_shell_commands_and_preserve_provenance():
    """
    P1-C Requirement: Tests that for provider API calls (LLM Auditor and Unverified PoC),
    no shell command is invented (argv and command are None), and provider, model_id,
    prompt_hash, and effective_config_hash are recorded in the manifest.
    """
    auditor_adapter = LLMAuditorBaselineAdapter(
        provider="google",
        model_id="gemini-2.5-flash",
        client_override=lambda prompt: '{"vulnerability_found": true, "vulnerability_type": "Reentrancy", "confidence": "High"}',
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_2"],
            custom_adapters={"baseline_2": auditor_adapter},
            save_results=True,
        )

        b2_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_2"]
        # API call has no subprocess: actual command and argv must be None
        assert b2_man["argv"] is None
        assert b2_man["command"] is None
        assert b2_man["planned_argv"] is None
        assert b2_man["planned_command"] is None

        for tid, t_prov in b2_man["per_target_provenance"].items():
            assert t_prov["argv"] is None
            assert t_prov["command"] is None
            assert t_prov["exit_code"] is None
            assert t_prov["provider"] == "google"
            assert t_prov["model_id"] == "gemini-2.5-flash"
            assert len(t_prov["prompt_hash"]) == 64
            assert t_prov["effective_config_hash"] == auditor_adapter.get_effective_config_hash()


def test_manifest_executed_subprocess_matches_exact_invocation_record_and_custom_overrides():
    """
    P1-C Requirement: Deliberately varies argv, config, and timeout on a subprocess adapter
    and asserts exact equality between the invocation record and the emitted manifest.
    """
    custom_budget = {"timeout_sec": 73, "custom_opt": "enabled", "worker_threads": 4}
    custom_tokens = ["custom_runner", "--special-flag", "--timeout=73"]

    class CustomSubprocessAdapter(BaselineAdapter):
        @property
        def baseline_id(self):
            return "baseline_1"
        @property
        def baseline_name(self):
            return "Custom Subprocess Adapter"
        @property
        def timeout_sec(self):
            return 73
        @property
        def resource_budget(self):
            return custom_budget
        def check_availability(self):
            return True, None
        def get_default_argv(self):
            return list(custom_tokens)
        def get_effective_config_hash(self):
            return hashlib.sha256(b"custom_config_unique_73").hexdigest()
        def execute_target(self, target, base_dir=None, timeout_sec=None):
            eff_timeout = timeout_sec or self.timeout_sec
            invocation_argv = list(custom_tokens) + ["--target", target.contract_id]
            stdout_text = f"executed target {target.contract_id}"
            stderr_text = ""
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.SUCCESS,
                detected=True,
                duration_seconds=0.05,
                argv=invocation_argv,
                timeout_sec=eff_timeout,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
                tool_metadata={
                    "exit_code": 0,
                    "stdout_sha256": hashlib.sha256(stdout_text.encode("utf-8")).hexdigest(),
                    "stderr_sha256": hashlib.sha256(stderr_text.encode("utf-8")).hexdigest(),
                },
                raw_output={"stdout": stdout_text, "stderr": stderr_text},
            )

    adapter = CustomSubprocessAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        assert b1_man["timeout_sec"] == 73
        assert b1_man["resource_budget"] == custom_budget
        assert b1_man["config_hash"] == adapter.get_effective_config_hash()
        assert b1_man["argv"] is None
        assert b1_man["command"] is None
        assert b1_man["planned_argv"] == custom_tokens
        assert b1_man["planned_command"] == " ".join(custom_tokens)

        # Invariant: assert exact equality between invocation record and manifest per-target entry
        for tid, t_prov in b1_man["per_target_provenance"].items():
            expected_argv = custom_tokens + ["--target", tid]
            assert t_prov["argv"] == expected_argv
            assert t_prov["command"] == " ".join(expected_argv)
            assert t_prov["timeout_sec"] == 73
            assert t_prov["resource_budget"] == custom_budget
            assert t_prov["effective_config_hash"] == adapter.get_effective_config_hash()
            assert t_prov["exit_code"] == 0
            expected_stdout_sha = hashlib.sha256(f"executed target {tid}".encode("utf-8")).hexdigest()
            assert t_prov["stdout_sha256"] == expected_stdout_sha
            assert t_prov["stderr_sha256"] == hashlib.sha256(b"").hexdigest()


def test_adapter_level_manifest_never_labels_template_as_actual_command():
    """
    P1-B Acceptance Gate: Proves that for a subprocess adapter whose actual per-target
    argv differs from its default planned template (e.g. contains real file paths instead of
    <target_path>), the adapter-level actual argv and command remain strictly None, and no
    adapter-level field labels the template as actual execution evidence.
    """
    template_tokens = ["slither", "<target_path>", "--json", "slither_out.json"]

    class MockDifferingSubprocessAdapter(BaselineAdapter):
        @property
        def baseline_id(self):
            return "baseline_1"
        @property
        def baseline_name(self):
            return "Mock Differing Adapter"
        def check_availability(self):
            return True, None
        def get_default_argv(self):
            return list(template_tokens)
        def get_effective_config_hash(self):
            return hashlib.sha256(b"differing_mock_config").hexdigest()
        def execute_target(self, target, base_dir=None, timeout_sec=None):
            # Target-specific argv that differs completely from template
            target_argv = ["slither", f"contracts/{target.contract_id}.sol", "--json", f"/tmp/{target.contract_id}.json"]
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.SUCCESS,
                detected=True,
                argv=target_argv,
                timeout_sec=45,
                resource_budget={"timeout_sec": 45},
                effective_config_hash=self.get_effective_config_hash(),
                tool_metadata={"exit_code": 0, "stdout_sha256": "abc", "stderr_sha256": "def"},
            )

    adapter = MockDifferingSubprocessAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]

        # 1. Assert no adapter-level field labels the template as actual
        assert b1_man["argv"] is None
        assert b1_man["command"] is None

        # 2. Assert planned template is preserved under planned_argv / planned_command
        assert b1_man["planned_argv"] == template_tokens
        assert b1_man["planned_command"] == "slither <target_path> --json slither_out.json"

        # 3. Assert per-target records contain the distinct actual executed argv
        for tid, t_prov in b1_man["per_target_provenance"].items():
            expected_target_argv = ["slither", f"contracts/{tid}.sol", "--json", f"/tmp/{tid}.json"]
            assert t_prov["argv"] == expected_target_argv
            assert t_prov["command"] == " ".join(expected_target_argv)
            assert "<target_path>" not in t_prov["argv"]


def test_manifest_uninvoked_artifacts_do_not_silently_fall_back_to_adapter_defaults():
    """
    P1-B & P1-C Requirement: Proves that when an artifact lacks invocation records (e.g. timeout,
    resource budget, config hash, exit code), the manifest per_target_provenance preserves null/None
    and does NOT silently fall back to adapter-level configured defaults.
    """
    class SparseMockAdapter(BaselineAdapter):
        @property
        def baseline_id(self):
            return "baseline_1"
        @property
        def baseline_name(self):
            return "Sparse Mock Adapter"
        @property
        def timeout_sec(self):
            return 99  # Should NOT leak into uninvoked targets
        @property
        def resource_budget(self):
            return {"timeout_sec": 99, "adapter_level_budget": True}  # Should NOT leak
        def check_availability(self):
            return True, None
        def get_default_argv(self):
            return ["sparse_runner"]
        def get_effective_config_hash(self):
            return "adapter_level_config_hash_should_not_leak"
        def execute_target(self, target, base_dir=None, timeout_sec=None):
            # Target artifact deliberately lacks invocation records
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason="Uninvoked sparse test",
                argv=None,
                timeout_sec=None,  # No invocation timeout
                resource_budget={},  # Empty resource budget
                effective_config_hash=None,  # No config hash
                tool_metadata={},  # No exit code or hashes
            )

    adapter = SparseMockAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        for tid, t_prov in b1_man["per_target_provenance"].items():
            assert t_prov["status"] == "UNAVAILABLE"
            assert t_prov["argv"] is None
            assert t_prov["command"] is None
            assert t_prov["exit_code"] is None
            # Invariant: Must NOT fall back to adapter.timeout_sec, adapter.resource_budget, or adapter.config_hash
            assert t_prov["timeout_sec"] is None
            assert t_prov["resource_budget"] is None
            assert t_prov["effective_config_hash"] is None


# =============================================================================
# Real Tool Integration Probes (Explicit NOT_RUN / SKIPPED Separation)
# =============================================================================

def test_real_slither_integration_is_not_run_when_binary_missing():
    """
    Real Slither host integration probe: strictly marked NOT_RUN / skipped
    when slither binary is not available on host system PATH.
    Does NOT count as empirical benchmark execution.
    """
    adapter = SlitherBaselineAdapter()
    is_avail, reason = adapter.check_availability()
    if not is_avail:
        pytest.skip(f"NOT_RUN: Real Slither integration unavailable: {reason}")
    # If binary exists, execute one real check
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]
    art = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)
    assert art.tool_metadata["slither_version"] != "unknown"


def test_real_foundry_integration_is_not_run_when_binary_missing():
    """
    Real Foundry host integration probe: strictly marked NOT_RUN / skipped
    when forge binary is not available on host system PATH or credentials missing.
    Does NOT count as empirical benchmark execution.
    """
    adapter = LLMNaiveFoundryBaselineAdapter()
    is_avail, reason = adapter.check_availability()
    if not is_avail:
        pytest.skip(f"NOT_RUN: Real Foundry integration unavailable: {reason}")
    # If binary exists, execute one real check
    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]
    art = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)
    assert art.tool_metadata["forge_version"] != "unknown"

