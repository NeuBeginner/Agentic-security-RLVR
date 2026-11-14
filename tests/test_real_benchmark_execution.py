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

import os
import shutil
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
    non_allowlisted = TargetSpecification(
        contract_id="UNKNOWN-01",
        target_name="UnknownUntrustedContract",
        source_file="benchmarks/targets/solidity/Vault.sol",
        harness_file="benchmarks/targets/solidity/VaultHarness.t.sol",
    )

    adapter = FullAegisRLVRBaselineAdapter()
    artifact = adapter.execute_target(non_allowlisted)

    assert artifact.status == ExecutionStatus.UNAVAILABLE
    assert "not in production trusted harness allowlist" in artifact.unavailable_reason
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0


def test_full_aegis_rlvr_modal_absent_fails_closed_no_local_fallback(monkeypatch):
    """When Modal credentials are absent, Baseline 5 must be UNAVAILABLE and strictly never fall back to local execution."""
    import sandbox.runner

    # 1. Strip Modal credentials from environment and modal.config
    monkeypatch.delenv("MODAL_TOKEN_ID", raising=False)
    monkeypatch.delenv("MODAL_TOKEN_SECRET", raising=False)
    try:
        import modal
        monkeypatch.setattr(modal.config.config, "get", lambda key, default=None: None)
    except Exception:
        pass

    # 2. Trap local sandbox execution: if local sandbox is called, raise an assertion error!
    def local_sandbox_trap(*args, **kwargs):
        raise AssertionError("VIOLATION: Full Aegis-RLVR silently fell back to local sandbox execution!")

    monkeypatch.setattr(sandbox.runner, "run_payload_in_sandbox", local_sandbox_trap)
    monkeypatch.setattr(sandbox.runner, "verify_independent_replay", local_sandbox_trap)

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]

    adapter = FullAegisRLVRBaselineAdapter()
    is_avail, reason = adapter.check_availability()
    assert is_avail is False
    assert "Modal authentication not configured" in (reason or "")

    artifact = adapter.execute_target(vault_target)
    assert artifact.status == ExecutionStatus.UNAVAILABLE
    assert "Modal authentication not configured" in (artifact.unavailable_reason or "")
    assert artifact.argv is None
    assert artifact.timeout_sec is None
    assert artifact.effective_config_hash is None
    assert artifact.resource_budget == {}
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0


def _mock_replay_response(payload_dict, *, container_id="hokkglpxczflmxlcnxxg"):
    """
    Build a complete replay response exactly as the Modal replay worker returns it.

    Since Iteration 14 the client refuses to accept a replay that does not carry
    the byte-exact artifacts, the real container identity and replay-specific
    timestamps, so the mock has to be a faithful worker response.
    """
    import base64

    candidate = (payload_dict.get("test_code") or "").encode("utf-8")
    harness = b"// repository-owned harness\ncontract VaultHarness {}\n"
    stdout = b'{"test/VaultHarness.t.sol:testExploit":{"status":"Success","reason":null}}\n'
    stderr = b""

    return {
        "reproduced": True,
        "container_id": container_id,
        "modal_runtime": {
            "app_id": {
                "status": "OBSERVED",
                "value": "ap-EDUitOwWeMrIdYbTh4kB63",
                "source": "modal.running_app().app_id",
            },
            "function_call_id": {
                "status": "OBSERVED",
                "value": "fc-8Hq2ZpQrVt3Lb",
                "source": "modal.current_function_call_id()",
            },
            "container_id": {
                "status": "OBSERVED",
                "value": container_id,
                "source": "MODAL_WORKER_ID of the running container",
            },
        },
        "command": "forge test --offline --json -vvvv",
        "argv": ["forge", "test", "--offline", "--json", "-vvvv"],
        "return_code": 0,
        "exit_code": 0,
        "harness_verdict": "BREACH",
        "harness_suite": "test/VaultHarness.t.sol",
        "invariant_violated": True,
        "category": "EXPLOIT_CONFIRMED",
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "stderr_b64": base64.b64encode(stderr).decode("ascii"),
        "candidate_b64": base64.b64encode(candidate).decode("ascii"),
        "harness_b64": base64.b64encode(harness).decode("ascii"),
        "utc_start_time": "2026-11-09T03:17:41Z",
        "utc_end_time": "2026-11-09T03:19:20Z",
    }


def test_full_aegis_rlvr_invokes_modal_remote_functions(monkeypatch, tmp_path):
    """When Modal is available, Baseline 5 must invoke real Modal remote functions and record remote provenance."""
    import modal_app
    from core.schemas import ResultCategory, ExploitPayload, AttackHypothesis

    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None))

    remote_exploit_calls = []
    remote_replay_calls = []
    remote_trajectory_calls = []

    def mock_verify_exploit_remote(target_dict, payload_dict):
        remote_exploit_calls.append((target_dict, payload_dict))
        return {
            "target_name": target_dict["name"],
            "vulnerability_type": "ReentrancyDrain",
            "poc_code": payload_dict.get("test_code", ""),
            "category": ResultCategory.INVARIANT_BREACH_UNREPLAYED.value,
            "reward_score": 0.50,
            "reward_components": {"generation": 0.05, "compilation": 0.10, "verification": 0.10, "invariant": 0.25},
            "is_verified": False,
            "reproducible": False,
            "feedback": "Remote EVM invariant breach achieved",
        }

    def mock_verify_replay_remote(target_dict, payload_dict):
        remote_replay_calls.append((target_dict, payload_dict))
        return _mock_replay_response(payload_dict)

    def mock_record_trajectory_remote(traj_dict):
        remote_trajectory_calls.append(traj_dict)
        return "/vol/models/trajectories/traj_123.json"

    monkeypatch.setattr(modal_app.verify_exploit_remote, "remote", mock_verify_exploit_remote)
    monkeypatch.setattr(modal_app.verify_replay_remote, "remote", mock_verify_replay_remote)
    monkeypatch.setattr(modal_app.record_trajectory_remote, "remote", mock_record_trajectory_remote)

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]

    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="ReentrancyDrain", reasoning_trace="Trace", attack_vector="Drain"),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )
    adapter = FullAegisRLVRBaselineAdapter(candidate_generator=lambda prog: dummy_payload)
    artifact = adapter.execute_target(vault_target, replay_artifact_dir=tmp_path)

    assert len(remote_exploit_calls) == 1
    assert len(remote_replay_calls) == 1
    assert len(remote_trajectory_calls) == 1

    assert artifact.status == ExecutionStatus.SUCCESS
    assert artifact.detected is True
    assert artifact.verified_breaches == 1
    assert artifact.replayed_breaches == 1
    assert artifact.tool_metadata["remote_backend"] == "modal"
    assert artifact.tool_metadata["modal_functions"] == ["verify_exploit_remote", "verify_replay_remote", "record_trajectory_remote"]
    assert artifact.tool_metadata["remote_stages"]["evm_sandbox"] == "modal_cpu_worker"
    assert artifact.tool_metadata["remote_stages"]["independent_replay"] == "modal_cpu_worker"
    assert artifact.tool_metadata["remote_stages"]["trajectory_persistence"] == "modal_volume"
    assert artifact.tool_metadata["reproduced"] is True
    # The replay envelope must be complete and re-validated by the client.
    assert artifact.tool_metadata["replay_envelope_valid"] is True
    assert artifact.replay_status == "CONFIRMED"
    assert artifact.replay_evidence["container_id"] == "hokkglpxczflmxlcnxxg"
    assert (tmp_path / "REENT-01_replay_stdout.txt").is_file()
    assert (tmp_path / "REENT-01_replay_candidate.sol").is_file()


def test_full_aegis_rlvr_remote_timeout_fails_closed(monkeypatch):
    """When a remote Modal worker times out, Baseline 5 must report FAILED fail-closed, never SUCCESS."""
    import modal_app
    from core.schemas import ExploitPayload, AttackHypothesis

    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None))

    def mock_timeout(target_dict, payload_dict):
        raise TimeoutError("Modal worker execution timed out (60s container limit)")

    monkeypatch.setattr(modal_app.verify_exploit_remote, "remote", mock_timeout)

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]

    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="ReentrancyDrain", reasoning_trace="Trace", attack_vector="Drain"),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )
    adapter = FullAegisRLVRBaselineAdapter(candidate_generator=lambda prog: dummy_payload)
    artifact = adapter.execute_target(vault_target)

    assert artifact.status == ExecutionStatus.FAILED
    assert "timed out" in (artifact.unavailable_reason or "").lower()
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0


def test_full_aegis_rlvr_remote_worker_exception_fails_closed(monkeypatch):
    """When a remote Modal worker raises an infrastructure exception, Baseline 5 must report FAILED."""
    import modal_app
    from core.schemas import ExploitPayload, AttackHypothesis

    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None))

    def mock_infra_error(target_dict, payload_dict):
        raise ConnectionResetError("Modal worker connection dropped by host")

    monkeypatch.setattr(modal_app.verify_exploit_remote, "remote", mock_infra_error)

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]

    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="ReentrancyDrain", reasoning_trace="Trace", attack_vector="Drain"),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )
    adapter = FullAegisRLVRBaselineAdapter(candidate_generator=lambda prog: dummy_payload)
    artifact = adapter.execute_target(vault_target)

    assert artifact.status == ExecutionStatus.FAILED
    assert "ConnectionResetError" in (artifact.unavailable_reason or "")
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0


def test_full_aegis_rlvr_replay_failure_prevents_verified_breach(monkeypatch):
    """When independent replay fails or reverts, candidate must remain unverified and not count as breach."""
    import modal_app
    from core.schemas import ResultCategory, ExploitPayload, AttackHypothesis

    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None))

    def mock_verify_exploit_remote(target_dict, payload_dict):
        return {
            "target_name": target_dict["name"],
            "vulnerability_type": "ReentrancyDrain",
            "poc_code": payload_dict.get("test_code", ""),
            "category": ResultCategory.INVARIANT_BREACH_UNREPLAYED.value,
            "reward_score": 0.50,
            "reward_components": {"generation": 0.05, "compilation": 0.10, "verification": 0.10, "invariant": 0.25},
            "is_verified": False,
            "reproducible": False,
            "feedback": "Initial invariant breach achieved, awaiting replay confirmation",
        }

    # Replay returns False (could not reproduce in clean container)
    monkeypatch.setattr(modal_app.verify_exploit_remote, "remote", mock_verify_exploit_remote)
    monkeypatch.setattr(modal_app.verify_replay_remote, "remote", lambda target_dict, payload_dict: False)

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]

    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="ReentrancyDrain", reasoning_trace="Trace", attack_vector="Drain"),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )
    adapter = FullAegisRLVRBaselineAdapter(candidate_generator=lambda prog: dummy_payload)
    artifact = adapter.execute_target(vault_target)

    assert artifact.status == ExecutionStatus.SUCCESS
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0
    assert artifact.tool_metadata["reproduced"] is False


def test_full_aegis_rlvr_replay_infrastructure_exception_fails_closed(monkeypatch):
    """When remote replay worker throws an exception (e.g. crash/timeout), adapter MUST return FAILED, never SUCCESS."""
    import modal_app
    from core.schemas import ResultCategory, ExploitPayload, AttackHypothesis

    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None))

    def mock_verify_exploit_remote(target_dict, payload_dict):
        return {
            "target_name": target_dict["name"],
            "vulnerability_type": "ReentrancyDrain",
            "poc_code": payload_dict.get("test_code", ""),
            "category": ResultCategory.INVARIANT_BREACH_UNREPLAYED.value,
            "reward_score": 0.50,
            "reward_components": {"generation": 0.05, "compilation": 0.10, "verification": 0.10, "invariant": 0.25},
            "is_verified": False,
            "reproducible": False,
            "feedback": "Initial invariant breach achieved, awaiting replay confirmation",
        }

    # Replay worker throws a real remote exception
    def mock_replay_throw(target_dict, payload_dict):
        raise ConnectionResetError("Modal replay worker connection dropped by host")

    monkeypatch.setattr(modal_app.verify_exploit_remote, "remote", mock_verify_exploit_remote)
    monkeypatch.setattr(modal_app.verify_replay_remote, "remote", mock_replay_throw)

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]

    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="ReentrancyDrain", reasoning_trace="Trace", attack_vector="Drain"),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )
    adapter = FullAegisRLVRBaselineAdapter(candidate_generator=lambda prog: dummy_payload)
    artifact = adapter.execute_target(vault_target)

    # Invariant: Must fail closed as FAILED, never SUCCESS!
    assert artifact.status == ExecutionStatus.FAILED
    assert "ConnectionResetError" in (artifact.unavailable_reason or "")
    assert "Modal remote replay infrastructure failure" in (artifact.unavailable_reason or "")
    assert artifact.detected is False
    assert artifact.verified_breaches == 0
    assert artifact.replayed_breaches == 0
    assert artifact.tool_metadata["stage_failed"] == "independent_replay"


def test_full_aegis_rlvr_trajectory_persistence_failure_recorded_properly(monkeypatch, tmp_path):
    """When trajectory persistence raises an exception, it must be recorded as failed, not reported as completed."""
    import modal_app
    from core.schemas import ResultCategory, ExploitPayload, AttackHypothesis

    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None))

    def mock_verify_exploit_remote(target_dict, payload_dict):
        return {
            "target_name": target_dict["name"],
            "vulnerability_type": "ReentrancyDrain",
            "poc_code": payload_dict.get("test_code", ""),
            "category": ResultCategory.INVARIANT_BREACH_UNREPLAYED.value,
            "reward_score": 0.50,
            "reward_components": {"generation": 0.05, "compilation": 0.10, "verification": 0.10, "invariant": 0.25},
            "is_verified": False,
            "reproducible": False,
            "feedback": "Remote EVM invariant breach achieved",
        }

    monkeypatch.setattr(modal_app.verify_exploit_remote, "remote", mock_verify_exploit_remote)
    monkeypatch.setattr(modal_app.verify_replay_remote, "remote", lambda td, pd: _mock_replay_response(pd))

    def mock_record_trajectory_throw(traj_dict):
        raise OSError("Modal volume disk quota exceeded (/vol/models full)")

    monkeypatch.setattr(modal_app.record_trajectory_remote, "remote", mock_record_trajectory_throw)

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]

    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="ReentrancyDrain", reasoning_trace="Trace", attack_vector="Drain"),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )
    adapter = FullAegisRLVRBaselineAdapter(candidate_generator=lambda prog: dummy_payload)
    artifact = adapter.execute_target(vault_target, replay_artifact_dir=tmp_path)

    assert artifact.status == ExecutionStatus.SUCCESS
    assert artifact.detected is True
    # Crucial assertion: record_trajectory_remote must NOT be in modal_functions when it failed!
    assert "record_trajectory_remote" not in artifact.tool_metadata["modal_functions"]
    assert artifact.tool_metadata["remote_stages"]["trajectory_persistence"] == "failed"
    assert artifact.tool_metadata["persistence_status"] == "failed"
    assert "Modal volume disk quota exceeded" in artifact.tool_metadata["persistence_error"]
    assert artifact.tool_metadata["persisted_trajectory_path"] is None


def test_full_aegis_rlvr_trajectory_persistence_success_recorded(monkeypatch, tmp_path):
    """When trajectory persistence succeeds, persisted path must be recorded and included in modal_functions."""
    import modal_app
    from core.schemas import ResultCategory, ExploitPayload, AttackHypothesis

    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None))

    def mock_verify_exploit_remote(target_dict, payload_dict):
        return {
            "target_name": target_dict["name"],
            "vulnerability_type": "ReentrancyDrain",
            "poc_code": payload_dict.get("test_code", ""),
            "category": ResultCategory.INVARIANT_BREACH_UNREPLAYED.value,
            "reward_score": 0.50,
            "reward_components": {"generation": 0.05, "compilation": 0.10, "verification": 0.10, "invariant": 0.25},
            "is_verified": False,
            "reproducible": False,
            "feedback": "Remote EVM invariant breach achieved",
        }

    monkeypatch.setattr(modal_app.verify_exploit_remote, "remote", mock_verify_exploit_remote)
    monkeypatch.setattr(modal_app.verify_replay_remote, "remote", lambda td, pd: _mock_replay_response(pd))
    monkeypatch.setattr(modal_app.record_trajectory_remote, "remote", lambda td: "/vol/models/trajectories/traj_vault_pass.json")

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]

    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="ReentrancyDrain", reasoning_trace="Trace", attack_vector="Drain"),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )
    adapter = FullAegisRLVRBaselineAdapter(candidate_generator=lambda prog: dummy_payload)
    artifact = adapter.execute_target(vault_target, replay_artifact_dir=tmp_path)

    assert artifact.status == ExecutionStatus.SUCCESS
    assert artifact.detected is True
    assert "record_trajectory_remote" in artifact.tool_metadata["modal_functions"]
    assert artifact.tool_metadata["remote_stages"]["trajectory_persistence"] == "modal_volume"
    assert artifact.tool_metadata["persistence_status"] == "persisted"
    assert artifact.tool_metadata["persisted_trajectory_path"] == "/vol/models/trajectories/traj_vault_pass.json"
    assert artifact.tool_metadata["persistence_error"] is None


def test_full_aegis_rlvr_explicit_inference_backend_naming():
    """Verify that Baseline 5 baseline_name explicitly describes its inference backend."""
    b_h100 = FullAegisRLVRBaselineAdapter(provider="modal_h100", model_id="Qwen3-Coder-30B-A3B-Audit")
    assert b_h100.baseline_name == "Full Aegis-RLVR (Modal H100 Reasoning + Modal CPU EVM Replay)"

    b_t4 = FullAegisRLVRBaselineAdapter(provider="modal_t4", model_id="Qwen2.5-Coder-1.5B-Instruct")
    assert b_t4.baseline_name == "Full Aegis-RLVR (Modal T4 Reasoning + Modal CPU EVM Replay)"

    b_gemini = FullAegisRLVRBaselineAdapter(provider="gemini", model_id="gemini-1.5-pro")
    assert b_gemini.baseline_name == "Full Aegis-RLVR (Gemini Frontier API Reasoning + Modal CPU EVM Replay)"

    b_openai = FullAegisRLVRBaselineAdapter(provider="openai", model_id="gpt-4o")
    assert b_openai.baseline_name == "Full Aegis-RLVR (OpenAI API Reasoning + Modal CPU EVM Replay)"


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

    # The failed target has no finding at all - it is not a negative finding.
    failed_detail = next(d for d in res.details if d["target_id"] == "T2")
    assert failed_detail["detected"] is None
    assert failed_detail["detection_state"] == "NOT_EVALUATED"
    # The report record of the same target states the same thing.
    failed_record = next(a for a in res.target_artifacts if a["target_id"] == "T2")
    assert failed_record["detected"] is None
    assert failed_record["detection_state"] == "NOT_EVALUATED"


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
        assert b1_man["timeout_sec"] is None
        assert b1_man["resource_budget"] == {}
        assert b1_man["config_hash"] is None
        # Planned template and configured defaults are stored separately
        assert b1_man["planned_argv"] == adapter.get_default_argv()
        assert b1_man["planned_command"] == " ".join(adapter.get_default_argv())
        assert b1_man["planned_timeout_sec"] == adapter.timeout_sec
        assert b1_man["planned_config_hash"] == adapter.get_effective_config_hash()

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
        # Adapter-level actuals must NOT be populated from configured adapter defaults
        assert b1_man["timeout_sec"] is None
        assert b1_man["resource_budget"] == {}
        assert b1_man["config_hash"] is None
        assert b1_man["argv"] is None
        assert b1_man["command"] is None
        # Planned metadata preserved
        assert b1_man["planned_timeout_sec"] == 99
        assert b1_man["planned_resource_budget"] == {"timeout_sec": 99, "adapter_level_budget": True}
        assert b1_man["planned_config_hash"] == "adapter_level_config_hash_should_not_leak"
        assert b1_man["planned_argv"] == ["sparse_runner"]

        for tid, t_prov in b1_man["per_target_provenance"].items():
            assert t_prov["status"] == "UNAVAILABLE"
            assert t_prov["argv"] is None
            assert t_prov["command"] is None
            assert t_prov["exit_code"] is None
            # Invariant: Must NOT fall back to adapter.timeout_sec, adapter.resource_budget, or adapter.config_hash
            assert t_prov["timeout_sec"] is None
            assert t_prov["resource_budget"] is None
            assert t_prov["effective_config_hash"] is None


def test_manifest_adapter_available_zero_targets_invoked_preserves_adapter_level_nulls():
    """
    Reviewer Requirement: When an adapter is available (check_availability() -> (True, None)),
    but zero targets are actually invoked (e.g. all targets return UNAVAILABLE), the adapter-level
    actual execution fields (timeout_sec, resource_budget, config_hash, argv, command) MUST remain
    null/empty, while planned/configured fields preserve the adapter defaults.
    """
    class AvailableButZeroInvokedAdapter(BaselineAdapter):
        @property
        def baseline_id(self):
            return "baseline_1"
        @property
        def baseline_name(self):
            return "Available Zero Invoked Adapter"
        @property
        def timeout_sec(self):
            return 75
        @property
        def resource_budget(self):
            return {"timeout_sec": 75, "configured": True}
        def check_availability(self):
            return True, None
        def get_default_argv(self):
            return ["tool_cli", "--target", "<target_path>"]
        def get_effective_config_hash(self):
            return "planned_config_hash_value_1234567890abcdef"
        def execute_target(self, target, base_dir=None, timeout_sec=None):
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason="Target pre-condition failed",
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
                tool_metadata={},
            )

    adapter = AvailableButZeroInvokedAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        # Adapter availability is True
        assert b1_man["availability_status"] == "AVAILABLE"
        # Actual adapter-level fields are strictly null / empty because 0 targets were invoked
        assert b1_man["argv"] is None
        assert b1_man["command"] is None
        assert b1_man["timeout_sec"] is None
        assert b1_man["resource_budget"] == {}
        assert b1_man["config_hash"] is None
        # Planned metadata preserves configured defaults
        assert b1_man["planned_argv"] == ["tool_cli", "--target", "<target_path>"]
        assert b1_man["planned_command"] == "tool_cli --target <target_path>"
        assert b1_man["planned_timeout_sec"] == 75
        assert b1_man["planned_resource_budget"] == {"timeout_sec": 75, "configured": True}
        assert b1_man["planned_config_hash"] == "planned_config_hash_value_1234567890abcdef"


def test_manifest_adapter_mixed_invoked_and_uninvoked_targets_leaves_adapter_actuals_null():
    """
    Reviewer Requirement: When an adapter runs multiple targets and has a mixture of invoked
    and uninvoked (UNAVAILABLE) targets, adapter-level actual execution fields must remain null/empty.
    One target's runtime values must NOT be claimed as the adapter-level execution value.
    """
    class MixedInvocationAdapter(BaselineAdapter):
        @property
        def baseline_id(self):
            return "baseline_1"
        @property
        def baseline_name(self):
            return "Mixed Invocation Adapter"
        @property
        def timeout_sec(self):
            return 80
        @property
        def resource_budget(self):
            return {"timeout_sec": 80}
        def check_availability(self):
            return True, None
        def get_default_argv(self):
            return ["mixed_cli", "<target_path>"]
        def get_effective_config_hash(self):
            return "adapter_level_mixed_hash"
        def execute_target(self, target, base_dir=None, timeout_sec=None):
            # Target REENT-01 is invoked and SUCCESS; all other targets are UNAVAILABLE
            if target.contract_id == "REENT-01":
                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.SUCCESS,
                    detected=True,
                    argv=["mixed_cli", f"contracts/{target.contract_id}.sol"],
                    timeout_sec=40,
                    resource_budget={"timeout_sec": 40},
                    effective_config_hash="reent01_invoked_hash",
                    tool_metadata={"exit_code": 0},
                )
            else:
                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.UNAVAILABLE,
                    unavailable_reason="Uninvoked target",
                    argv=None,
                    timeout_sec=None,
                    resource_budget={},
                    effective_config_hash=None,
                    tool_metadata={},
                )

    adapter = MixedInvocationAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        # Invariant: Because not all targets were invoked, adapter-level actual fields are null/empty
        assert b1_man["argv"] is None
        assert b1_man["command"] is None
        assert b1_man["timeout_sec"] is None
        assert b1_man["resource_budget"] == {}
        assert b1_man["config_hash"] is None

        # Planned metadata preserves adapter defaults
        assert b1_man["planned_timeout_sec"] == 80
        assert b1_man["planned_resource_budget"] == {"timeout_sec": 80}
        assert b1_man["planned_config_hash"] == "adapter_level_mixed_hash"

        # Per-target records: REENT-01 has exact execution values; others have nulls
        reent_prov = b1_man["per_target_provenance"]["REENT-01"]
        assert reent_prov["status"] == "SUCCESS"
        assert reent_prov["argv"] == ["mixed_cli", "contracts/REENT-01.sol"]
        assert reent_prov["timeout_sec"] == 40
        assert reent_prov["effective_config_hash"] == "reent01_invoked_hash"

        for tid, t_prov in b1_man["per_target_provenance"].items():
            if tid != "REENT-01":
                assert t_prov["status"] == "UNAVAILABLE"
                assert t_prov["argv"] is None
                assert t_prov["timeout_sec"] is None
                assert t_prov["resource_budget"] is None
                assert t_prov["effective_config_hash"] is None


def test_manifest_adapter_differing_target_execution_values_leaves_adapter_actuals_null():
    """
    Reviewer Requirement: When multiple targets are invoked with different actual timeout,
    resource budget, or config hash values, the adapter-level actual fields must remain null/empty.
    No single target's value may be claimed as representing the whole adapter.
    """
    class DifferingTargetValuesAdapter(BaselineAdapter):
        @property
        def baseline_id(self):
            return "baseline_1"
        @property
        def baseline_name(self):
            return "Differing Values Adapter"
        @property
        def timeout_sec(self):
            return 50
        @property
        def resource_budget(self):
            return {"timeout_sec": 50}
        def check_availability(self):
            return True, None
        def get_default_argv(self):
            return ["differing_cli", "<target_path>"]
        def get_effective_config_hash(self):
            return "adapter_level_hash"
        def execute_target(self, target, base_dir=None, timeout_sec=None):
            # Target REENT-01 runs with timeout 25; all other targets run with timeout 50
            t_timeout = 25 if target.contract_id == "REENT-01" else 50
            t_hash = f"hash_for_{target.contract_id}"
            t_budget = {"timeout_sec": t_timeout, "target": target.contract_id}
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.SUCCESS,
                detected=True,
                argv=["differing_cli", f"contracts/{target.contract_id}.sol"],
                timeout_sec=t_timeout,
                resource_budget=t_budget,
                effective_config_hash=t_hash,
                tool_metadata={"exit_code": 0},
            )

    adapter = DifferingTargetValuesAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        # Invariant: Because timeouts, budgets, and config hashes differ across targets,
        # adapter-level actual execution fields are strictly null/empty
        assert b1_man["timeout_sec"] is None
        assert b1_man["resource_budget"] == {}
        assert b1_man["config_hash"] is None
        assert b1_man["argv"] is None
        assert b1_man["command"] is None

        # Planned metadata reflects configured adapter defaults
        assert b1_man["planned_timeout_sec"] == 50
        assert b1_man["planned_resource_budget"] == {"timeout_sec": 50}
        assert b1_man["planned_config_hash"] == "adapter_level_hash"

        # Per-target records preserve the exact differing runtime values
        assert b1_man["per_target_provenance"]["REENT-01"]["timeout_sec"] == 25
        assert b1_man["per_target_provenance"]["REENT-01"]["effective_config_hash"] == "hash_for_REENT-01"
        assert b1_man["per_target_provenance"]["AC-01"]["timeout_sec"] == 50
        assert b1_man["per_target_provenance"]["AC-01"]["effective_config_hash"] == "hash_for_AC-01"


def test_manifest_missing_target_file_pre_invocation_failure_leaves_adapter_actuals_null():
    """
    Reviewer Requirement: When a real baseline adapter (SlitherBaselineAdapter) encounters a missing
    target file or pre-invocation failure, the target status is UNAVAILABLE and the manifest adapter-level
    actual execution fields are null/empty.
    """
    adapter = SlitherBaselineAdapter(timeout_sec=45)
    # Mock check_availability to return True so adapter is considered available
    adapter.check_availability = lambda: (True, None)

    # Use a target with non-existent source file
    missing_target = TargetSpecification(
        contract_id="NONEXISTENT-01",
        target_name="MissingContract",
        source_file="does/not/exist/MissingContract.sol",
        harness_file="does/not/exist/MissingHarness.sol",
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        art = adapter.execute_target(missing_target, base_dir=Path(tmpdir))
        assert art.status == ExecutionStatus.FAILED
        assert "not found" in (art.unavailable_reason or "").lower()
        assert art.argv is None
        assert art.timeout_sec is None
        assert art.resource_budget == {}
        assert art.effective_config_hash is None

        # Run within suite
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        # Override public targets to just the missing target
        suite.dataset.targets = [missing_target]
        suite.dataset.ground_truth = {
            "NONEXISTENT-01": GroundTruth(
                contract_id="NONEXISTENT-01",
                is_vulnerable=True,
                vulnerable_functions=["attack"],
                ground_truth_invariant="NONE",
            )
        }

        rep = suite.run_benchmark(
            mode="real",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
            require_clean=False,
        )

        b1_man = rep["reproducibility_manifest_summary"]["adapters"]["baseline_1"]
        assert b1_man["availability_status"] == "AVAILABLE"
        # Actual execution evidence is null / empty
        assert b1_man["argv"] is None
        assert b1_man["command"] is None
        assert b1_man["timeout_sec"] is None
        assert b1_man["resource_budget"] == {}
        assert b1_man["config_hash"] is None
        # Planned metadata preserved
        assert b1_man["planned_timeout_sec"] == 45
        assert b1_man["planned_argv"] == adapter.get_default_argv()
        assert b1_man["planned_command"] == " ".join(adapter.get_default_argv())


def test_manifest_serialization_round_trip_preserves_null_vs_planned_values():
    """
    Reviewer Requirement: Verifies full JSON serialization round-trip of the reproducibility manifest.
    Asserts that null/empty actual execution fields stay null/empty, and planned metadata fields
    preserve their exact types, tokens, integers, and structures without mutation or data loss.
    """
    class RoundTripMockAdapter(BaselineAdapter):
        @property
        def baseline_id(self):
            return "baseline_1"
        @property
        def baseline_name(self):
            return "Round Trip Mock Adapter"
        @property
        def timeout_sec(self):
            return 65
        @property
        def resource_budget(self):
            return {"timeout_sec": 65, "custom_key": "custom_val"}
        def check_availability(self):
            return True, None
        def get_default_argv(self):
            return ["rt_tool", "<target_path>", "--opt"]
        def get_effective_config_hash(self):
            return "rt_planned_hash_abcdef123456"
        def execute_target(self, target, base_dir=None, timeout_sec=None):
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason="Uninvoked for serialization test",
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
                tool_metadata={},
            )

    adapter = RoundTripMockAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            custom_adapters={"baseline_1": adapter},
            save_results=True,
        )

        manifest_summary = rep["reproducibility_manifest_summary"]

        # Serialize to JSON string
        serialized_json = json.dumps(manifest_summary, indent=2)

        # Deserialize back
        deserialized = json.loads(serialized_json)

        b1_deser = deserialized["adapters"]["baseline_1"]

        # Invariant: Actual execution fields remain null/empty in deserialized JSON
        assert b1_deser["argv"] is None
        assert b1_deser["command"] is None
        assert b1_deser["timeout_sec"] is None
        assert b1_deser["resource_budget"] == {}
        assert b1_deser["config_hash"] is None

        # Invariant: Planned metadata fields retain exact configured values
        assert b1_deser["planned_argv"] == ["rt_tool", "<target_path>", "--opt"]
        assert b1_deser["planned_command"] == "rt_tool <target_path> --opt"
        assert b1_deser["planned_timeout_sec"] == 65
        assert b1_deser["planned_resource_budget"] == {"timeout_sec": 65, "custom_key": "custom_val"}
        assert b1_deser["planned_config_hash"] == "rt_planned_hash_abcdef123456"

        # Per-target records preserve null actuals
        for tid, t_prov in b1_deser["per_target_provenance"].items():
            assert t_prov["status"] == "UNAVAILABLE"
            assert t_prov["argv"] is None
            assert t_prov["command"] is None
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


def test_real_foundry_integration_live_execution():
    return test_real_foundry_integration_confirmed_exploit_breach()


def test_real_foundry_integration_confirmed_exploit_breach():
    """
    Deterministic Live Foundry positive integration test: executes repo-owned Vault target
    and VaultTrustedHarness with a real reentrancy ExploitModule.
    Asserts exact command, test success, returncode 0, and SecurityInvariantBreached.
    In CI (FOUNDRY_CI=true), forge MUST be on PATH.
    """
    is_foundry_ci = os.environ.get("FOUNDRY_CI") == "true"
    forge_path = shutil.which("forge")

    if is_foundry_ci:
        assert forge_path is not None, (
            "Foundry binary 'forge' MUST be present on PATH in CI integration runs. "
            "Missing binary fallback is strictly prohibited in CI."
        )

    if not forge_path:
        pytest.skip("NOT_RUN: Real Foundry integration unavailable on system PATH")

    from core.schemas import TargetProgram, ExploitPayload, AttackHypothesis, ResultCategory
    from sandbox.runner import run_payload_in_sandbox, HARNESS_VERDICT_BREACH

    vault_src = Path("benchmarks/targets/solidity/Vault.sol").read_text(encoding="utf-8")
    target = TargetProgram(
        name="Vault",
        source_code=vault_src,
        invariants=["DEPOSITOR_SOLVENCY_COLLAPSE"],
    )

    exploit_code = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        'import {Vault} from "../src/Vault.sol";\n\n'
        "contract ExploitModule {\n"
        "    Vault public targetContract;\n\n"
        "    constructor(address _target) payable {\n"
        "        targetContract = Vault(payable(_target));\n"
        "    }\n\n"
        "    function runExploit() external payable {\n"
        "        targetContract.deposit{value: msg.value}();\n"
        "        targetContract.withdrawAll();\n"
        "    }\n\n"
        "    receive() external payable {\n"
        "        if (address(targetContract).balance >= 1 ether) {\n"
        "            targetContract.withdrawAll();\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    payload = ExploitPayload(
        target_name="Vault",
        test_code=exploit_code,
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Vault allows reentrant withdrawal before updating balance",
            attack_vector="Call withdrawAll reentrantly via fallback",
        ),
        format_valid=True,
    )

    result = run_payload_in_sandbox(target, payload)

    assert result.return_code == 0, f"Forge failed with return code {result.return_code}: {result.stderr}"
    assert result.invariant_violated is True, "Expected invariant_violated to be True"
    assert result.category == ResultCategory.EXPLOIT_CONFIRMED, f"Expected EXPLOIT_CONFIRMED, got {result.category}"
    assert result.harness_verdict == HARNESS_VERDICT_BREACH
    assert "[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]" in (result.stdout + result.stderr)


def test_real_foundry_integration_compilation_failure():
    """
    Deterministic Live Foundry negative integration test: executes repo-owned Vault target
    with a deliberately syntax-broken ExploitModule.
    Asserts non-zero returncode, COMPILATION_ERROR category, and zero invariant breach.
    In CI (FOUNDRY_CI=true), forge MUST be on PATH.
    """
    is_foundry_ci = os.environ.get("FOUNDRY_CI") == "true"
    forge_path = shutil.which("forge")

    if is_foundry_ci:
        assert forge_path is not None, (
            "Foundry binary 'forge' MUST be present on PATH in CI integration runs. "
            "Missing binary fallback is strictly prohibited in CI."
        )

    if not forge_path:
        pytest.skip("NOT_RUN: Real Foundry integration unavailable on system PATH")

    from core.schemas import TargetProgram, ExploitPayload, AttackHypothesis, ResultCategory
    from sandbox.runner import run_payload_in_sandbox

    vault_src = Path("benchmarks/targets/solidity/Vault.sol").read_text(encoding="utf-8")
    target = TargetProgram(
        name="Vault",
        source_code=vault_src,
        invariants=["DEPOSITOR_SOLVENCY_COLLAPSE"],
    )

    broken_code = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        "contract ExploitModule {\n"
        "    DELIBERATE_SYNTAX_ERROR_FOR_COMPILATION_TEST();\n"
        "}\n"
    )

    payload = ExploitPayload(
        target_name="Vault",
        test_code=broken_code,
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Deliberately broken syntax for negative test",
            attack_vector="Broken syntax",
        ),
        format_valid=True,
    )

    result = run_payload_in_sandbox(target, payload)

    assert result.return_code != 0, f"Expected non-zero return code for broken syntax, got {result.return_code}"
    assert result.category == ResultCategory.COMPILATION_ERROR, (
        f"Expected COMPILATION_ERROR category, got {result.category}"
    )
    assert result.invariant_violated is False
    assert result.verified_by_harness is False


def test_real_foundry_integration_is_not_run_when_binary_missing(monkeypatch):
    """
    Real Foundry missing-binary probe: verifies that when forge binary is absent from PATH,
    the adapter correctly identifies unavailability, sets status to UNAVAILABLE, and does NOT
    attempt subprocess execution.
    """
    monkeypatch.setattr(shutil, "which", lambda cmd: None if cmd == "forge" else shutil.which(cmd))
    adapter = LLMNaiveFoundryBaselineAdapter()
    is_avail, reason = adapter.check_availability()
    assert is_avail is False
    assert "forge executable not found on system PATH" in (reason or "")

    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]
    art = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)
    assert art.status == ExecutionStatus.UNAVAILABLE
    assert "forge executable not found" in (art.unavailable_reason or "")
    assert art.security_verdict == "UNAVAILABLE"


# =============================================================================
# Baseline 5 Dedicated Inference Backend & CLI Routing Tests
# =============================================================================

def test_runner_routes_baseline5_provider_explicitly(tmpdir, monkeypatch):
    """
    Tests that AegisBenchmarkSuite correctly routes dedicated Baseline 5
    provider options (modal_h100, modal_t4) without affecting Baselines 2-4.
    """
    suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))

    # Test modal_h100 routing
    instantiated_adapters = {}
    orig_full_init = FullAegisRLVRBaselineAdapter.__init__

    def mock_init(self, *args, **kwargs):
        orig_full_init(self, *args, **kwargs)
        instantiated_adapters["baseline_5"] = self

    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "__init__", mock_init)

    # Fast mock of execution to prevent live calls during routing verification
    monkeypatch.setattr(
        FullAegisRLVRBaselineAdapter,
        "execute_target",
        lambda self, target, base_dir=None: TargetExecutionArtifact(
            baseline_id="baseline_5",
            target_id=target.contract_id,
            target_name=target.target_name,
            status=ExecutionStatus.SUCCESS,
            detected=False,
            candidates_generated=0,
            verified_breaches=0,
            replayed_breaches=0,
            duration_seconds=0.01,
            argv=None,
            timeout_sec=None,
            resource_budget={},
            effective_config_hash=None,
        )
    )

    report = suite.run_benchmark(
        mode="real",
        provider="gemini",
        baseline5_provider="modal_h100",
        baselines_to_run=["baseline_5"],
        save_results=False,
        require_clean=False,
    )

    b5_adapter = instantiated_adapters["baseline_5"]
    assert b5_adapter.provider == "modal_h100"
    assert b5_adapter.model_id == "qtum/Qwen3-Coder-30B-A3B-Audit"
    assert "Modal H100 Reasoning" in b5_adapter.baseline_name
    assert report["baseline5_provider"] == "modal_h100"
    assert report["baseline5_model_id"] == "qtum/Qwen3-Coder-30B-A3B-Audit"


def test_runner_cli_rejects_ambiguous_provider_configurations(tmpdir):
    """
    Tests that ambiguous or invalid provider configurations are rejected with clear ValueErrors.
    """
    suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))

    # 1. Reject invalid Baseline 5 provider
    with pytest.raises(ValueError, match="Invalid Baseline 5 provider 'unsupported_backend'"):
        suite.run_benchmark(
            mode="real",
            provider="gemini",
            baseline5_provider="unsupported_backend",
            baselines_to_run=["baseline_5"],
            save_results=False,
        )

    # 2. Reject passing modal_h100 as global provider when Baselines 2-4 are active
    with pytest.raises(ValueError, match="Invalid provider 'modal_h100' for Baselines 2-4"):
        suite.run_benchmark(
            mode="real",
            provider="modal_h100",
            baselines_to_run=["baseline_2", "baseline_5"],
            save_results=False,
        )


def test_runner_preserves_distinct_providers_for_baselines_2_4_and_baseline_5(tmpdir, monkeypatch):
    """
    Tests that when running mixed baselines, Baselines 2-4 use standard API provider (e.g. gemini)
    while Baseline 5 uses dedicated Modal H100 provider.
    """
    suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
    created = {}

    orig_b2_init = LLMAuditorBaselineAdapter.__init__
    def mock_b2(self, *args, **kwargs):
        orig_b2_init(self, *args, **kwargs)
        created["baseline_2"] = self

    orig_b5_init = FullAegisRLVRBaselineAdapter.__init__
    def mock_b5(self, *args, **kwargs):
        orig_b5_init(self, *args, **kwargs)
        created["baseline_5"] = self

    monkeypatch.setattr(LLMAuditorBaselineAdapter, "__init__", mock_b2)
    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "__init__", mock_b5)

    # Mock execute_target for fast routing check
    dummy_art = lambda b_id, target: TargetExecutionArtifact(
        baseline_id=b_id,
        target_id=target.contract_id,
        target_name=target.target_name,
        status=ExecutionStatus.SUCCESS,
        detected=False,
        candidates_generated=0,
        verified_breaches=0,
        replayed_breaches=0,
        duration_seconds=0.01,
        argv=None,
        timeout_sec=None,
        resource_budget={},
        effective_config_hash=None,
    )
    monkeypatch.setattr(LLMAuditorBaselineAdapter, "execute_target", lambda self, target, base_dir=None: dummy_art("baseline_2", target))
    monkeypatch.setattr(FullAegisRLVRBaselineAdapter, "execute_target", lambda self, target, base_dir=None: dummy_art("baseline_5", target))

    report = suite.run_benchmark(
        mode="real",
        provider="gemini",
        model_id="gemini-2.5-pro",
        baseline5_provider="modal_h100",
        baselines_to_run=["baseline_2", "baseline_5"],
        save_results=False,
        require_clean=False,
    )

    assert created["baseline_2"].provider == "gemini"
    assert created["baseline_2"].model_id == "gemini-2.5-pro"
    assert created["baseline_5"].provider == "modal_h100"
    assert created["baseline_5"].model_id == "qtum/Qwen3-Coder-30B-A3B-Audit"
    assert report["provider"] == "gemini"
    assert report["baseline5_provider"] == "modal_h100"


def test_full_aegis_rlvr_modal_h100_records_audit_agent_function_and_token_provenance(monkeypatch):
    """
    Tests that FullAegisRLVRBaselineAdapter on modal_h100 provider:
    - Lists ProductionAuditAgent.generate_solidity_exploit in modal_functions
    - Records token_provenance='model_generate' and exact generated_tokens_count
    """
    adapter = FullAegisRLVRBaselineAdapter(provider="modal_h100")
    monkeypatch.setattr(adapter, "check_availability", lambda: (True, None))

    class MockAgent:
        def generate_solidity_exploit(self):
            pass

    class RemoteMock:
        @staticmethod
        def remote(target_dict):
            return {
                "candidate_id": "test_h100_cand",
                "target_name": "Vault",
                "hypothesis": {"vulnerability_type": "Reentrancy", "reasoning_trace": "test", "attack_vector": "direct"},
                "test_code": "contract ExploitModule { function runExploit() external {} }",
                "format_valid": True,
                "generated_token_ids": [101, 102, 103, 104, 105],
                "prompt_text": "analysis prompt",
            }

    from contextlib import nullcontext
    monkeypatch.setattr("benchmarks.adapters.ensure_modal_app_context", lambda: nullcontext())

    import modal_app
    class MockProdAgent:
        generate_solidity_exploit = RemoteMock()
    monkeypatch.setattr(modal_app, "ProductionAuditAgent", MockProdAgent)
    monkeypatch.setattr(
        modal_app,
        "verify_exploit_remote",
        type("obj", (), {"remote": staticmethod(lambda t, p: {
            "target_name": "Vault",
            "vulnerability_type": "Reentrancy",
            "poc_code": "contract ExploitModule { function runExploit() external {} }",
            "category": "SAFE_RUN",
            "reward_score": -0.1,
            "is_verified": False,
            "feedback": "Safe",
        })})()
    )

    dataset = BenchmarkDataset()
    target = dataset.get_public_targets()[0]
    art = adapter.execute_target(target, base_dir=Path(__file__).parent.parent)

    assert art.unavailable_reason is None
    assert art.status == ExecutionStatus.SUCCESS
    assert "ProductionAuditAgent.generate_solidity_exploit" in art.tool_metadata["modal_functions"]
    assert art.tool_metadata["token_provenance"] == "model_generate"
    assert art.tool_metadata["generated_tokens_count"] == 5
    assert art.tool_metadata["inference_backend"] == "modal_h100"


def test_manifest_git_integrity_rejects_non_40_char_or_special_shas():
    """Manifest git integrity validation must strictly reject 'HEAD', 'unknown', or abbreviated SHAs."""
    from benchmarks.protocol import validate_manifest_git_integrity, verify_manifest_git_integrity

    invalid_shas = ["HEAD", "unknown", "c1813a7", "118d644", "", "not_a_hex_string_with_forty_characters_12345"]
    for bad_sha in invalid_shas:
        manifest = {
            "run_id": "run_1794146412_c1813a7",
            "git": {"commit_sha": bad_sha, "is_dirty": False, "branch": "main"}
        }
        valid, err = validate_manifest_git_integrity(manifest)
        assert valid is False, f"Expected rejection for bad SHA '{bad_sha}'"
        assert ("Invalid git commit SHA" in err) or ("Missing or non-string" in err)

        with pytest.raises(ValueError, match="Reproducibility manifest git integrity validation failed"):
            verify_manifest_git_integrity(manifest)


def test_manifest_git_integrity_rejects_sha_mismatch_with_checkout():
    """Manifest git integrity validation must reject manifests whose full SHA does not match expected checkout."""
    from benchmarks.protocol import validate_manifest_git_integrity, verify_manifest_git_integrity

    manifest_sha = "c1813a78c08952e34eb1afdac5b4cf5752547e79"
    checkout_sha = "118d6447209930f36f901193d56f69e6b4ad2327"

    manifest = {
        "run_id": f"run_1794146412_{manifest_sha[:7]}",
        "git": {"commit_sha": manifest_sha, "is_dirty": False, "branch": "feat/empirical-benchmark-runner"}
    }

    valid, err = validate_manifest_git_integrity(manifest, expected_commit_sha=checkout_sha)
    assert valid is False
    assert "does not match expected checkout SHA" in err

    with pytest.raises(ValueError, match="does not match expected checkout SHA"):
        verify_manifest_git_integrity(manifest, expected_commit_sha=checkout_sha)


def test_manifest_git_integrity_rejects_run_dir_suffix_inconsistency():
    """Manifest git integrity validation must reject inconsistent run-directory suffix and manifest commit SHA."""
    from benchmarks.protocol import validate_manifest_git_integrity, verify_manifest_git_integrity

    manifest_sha = "c1813a78c08952e34eb1afdac5b4cf5752547e79"
    mismatched_dir = "benchmarks/artifacts/run_1794146412_118d644"

    manifest = {
        "run_id": "run_1794146412_118d644",
        "git": {"commit_sha": manifest_sha, "is_dirty": False, "branch": "feat/empirical-benchmark-runner"}
    }

    valid, err = validate_manifest_git_integrity(manifest, run_dir=mismatched_dir)
    assert valid is False
    assert "Run directory suffix '118d644' does not match manifest commit prefix 'c1813a7'" in err

    with pytest.raises(ValueError, match="Run directory suffix '118d644' does not match manifest commit prefix 'c1813a7'"):
        verify_manifest_git_integrity(manifest, run_dir=mismatched_dir)


def test_manifest_git_integrity_accepts_valid_consistent_manifest():
    """Manifest git integrity validation must accept consistent 40-char SHA matching checkout and run dir."""
    from benchmarks.protocol import validate_manifest_git_integrity, verify_manifest_git_integrity

    full_sha = "c1813a78c08952e34eb1afdac5b4cf5752547e79"
    run_dir = f"benchmarks/artifacts/run_1794146412_{full_sha[:7]}"

    manifest = {
        "run_id": f"run_1794146412_{full_sha[:7]}",
        "git": {"commit_sha": full_sha, "is_dirty": False, "branch": "feat/empirical-benchmark-runner"}
    }

    valid, err = validate_manifest_git_integrity(manifest, run_dir=run_dir, expected_commit_sha=full_sha)
    assert valid is True
    assert err is None
    # Must not raise
    verify_manifest_git_integrity(manifest, run_dir=run_dir, expected_commit_sha=full_sha)


def test_benchmark_runner_enforces_manifest_git_integrity_on_execution():
    """AegisBenchmarkSuite.run_benchmark must produce a manifest that passes git integrity validation."""
    from benchmarks.protocol import verify_manifest_git_integrity

    with tempfile.TemporaryDirectory() as tmpdir:
        suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
        rep = suite.run_benchmark(mode="smoke", baselines_to_run=["baseline_1"], save_results=True)

        manifest_summary = rep["reproducibility_manifest_summary"]
        commit_sha = rep["git_commit_sha"]
        if commit_sha != "unknown":
            verify_manifest_git_integrity(
                manifest_summary,
                run_dir=rep["artifacts_directory"],
                expected_commit_sha=commit_sha
            )




# =============================================================================
# Iteration 10 Regression Suite: 16-Target Scope, Verification Statuses & Provenance
# =============================================================================

def test_16_target_scope_and_allowlist_consistency():
    """
    Verifies that all 16 benchmark targets (12 vulnerable targets + 4 synthetic safe controls)
    are consistently defined in benchmark_dataset.json, exist on disk with valid Solidity source,
    have dedicated immutable test harnesses on disk, and are fully recognized in
    TRUSTED_HARNESS_CONTRACTS and FullAegisRLVRBaselineAdapter.
    """
    from sandbox.runner import TRUSTED_HARNESS_CONTRACTS

    dataset = BenchmarkDataset()
    public_targets = dataset.get_public_targets()
    assert len(public_targets) == 16, f"Expected 16 targets, got {len(public_targets)}"

    base_dir = Path(__file__).parent.parent
    adapter = FullAegisRLVRBaselineAdapter()
    allowlist = adapter.allowlist

    for target in public_targets:
        # 1. Source file exists on disk
        src_path = base_dir / target.source_file
        assert src_path.exists(), f"Source file {src_path} for target {target.contract_id} not found"

        # 2. Target contract is in TRUSTED_HARNESS_CONTRACTS
        assert target.target_name in TRUSTED_HARNESS_CONTRACTS, (
            f"Target {target.target_name} ({target.contract_id}) missing from TRUSTED_HARNESS_CONTRACTS"
        )

        # 3. Harness file exists on disk and harness contract name is mapped
        harness_contract_name = TRUSTED_HARNESS_CONTRACTS[target.target_name]
        assert isinstance(harness_contract_name, str) and harness_contract_name
        assert target.harness_file, f"Target {target.target_name} lacks harness_file"
        harness_path = base_dir / target.harness_file
        assert harness_path.exists(), f"Harness file {harness_path} for target {target.target_name} not found"

        # 4. Target is in adapter allowlist
        assert target.target_name in allowlist, (
            f"Target {target.target_name} missing from FullAegisRLVRBaselineAdapter allowlist"
        )


def test_mixed_execution_and_security_statuses_separated():
    """
    Verifies strict separation between process execution status (ExecutionStatus: SUCCESS/FAILED/UNAVAILABLE)
    and EVM security verdicts (COMPILATION_ERROR, NO_BREACH, INVARIANT_BREACH, EXPLOIT_CONFIRMED),
    as well as replay_status and persistence_status.
    """
    art = TargetExecutionArtifact(
        baseline_id="baseline_5",
        target_id="REENT-01",
        target_name="Vault",
        status=ExecutionStatus.SUCCESS,
        security_verdict="NO_BREACH",
        replay_status="NOT_ELIGIBLE",
        persistence_status="NOT_ELIGIBLE",
        process_exit_code=0,
    )
    d = art.to_dict()
    assert d["status"] == "SUCCESS"
    assert d["execution_status"] == "SUCCESS"
    assert d["security_verdict"] == "NO_BREACH"
    assert d["replay_status"] == "NOT_ELIGIBLE"
    assert d["persistence_status"] == "NOT_ELIGIBLE"
    assert d["process_exit_code"] == 0

    art_fail = TargetExecutionArtifact(
        baseline_id="baseline_5",
        target_id="REENT-01",
        target_name="Vault",
        status=ExecutionStatus.FAILED,
        security_verdict="COMPILATION_ERROR",
        replay_status="NOT_ELIGIBLE",
        persistence_status="NOT_ELIGIBLE",
        process_exit_code=1,
    )
    d_fail = art_fail.to_dict()
    assert d_fail["status"] == "FAILED"
    assert d_fail["execution_status"] == "FAILED"
    assert d_fail["security_verdict"] == "COMPILATION_ERROR"


def test_compilation_failure_never_counted_as_exploit_or_breach():
    """
    P0 Guarantee: Evaluator must NEVER treat a compilation error as a detected exploit,
    invariant breach, or true positive, even if a buggy adapter marked detected=True.

    A **failed** execution produced no finding at all: its detection is None and
    its detection state is NOT_EVALUATED - never a negative finding.
    """
    dataset = BenchmarkDataset()
    gt_map = dataset.ground_truth

    # Synthesize an artifact with compilation failure but erroneously set detected=True
    artifact = TargetExecutionArtifact(
        baseline_id="baseline_4",
        target_id="REENT-01",
        target_name="Vault",
        status=ExecutionStatus.FAILED,
        security_verdict="COMPILATION_ERROR",
        detected=True,  # buggy signal
        verified_breaches=1,  # buggy signal
        replayed_breaches=0,
        duration_seconds=1.0,
    )

    eval_res = evaluate_baseline_run(
        baseline_id="baseline_4",
        baseline_name="LLM + Naive Foundry",
        artifacts=[artifact],
        ground_truth_map=gt_map,
    )
    # Because 1 target out of 16 was provided and it failed, overall status is FAILED
    assert eval_res.status == ExecutionStatus.FAILED
    assert eval_res.true_positives is None  # fail-closed metrics are None
    detail = eval_res.details[0]
    # The execution did not complete: there is no finding, not a negative one.
    assert detail["detected"] is None
    assert detail["detection_state"] == "NOT_EVALUATED"
    assert detail["verified_breaches"] == 0
    # The report record of the same target states the same thing.
    record = eval_res.target_artifacts[0]
    assert record["detected"] is None
    assert record["detection_state"] == "NOT_EVALUATED"
    assert record["verified_breaches"] == 0
    # The raw claim of the producer is preserved, not presented as a finding.
    assert record["producer_detected"] is True


def test_target_artifact_preserves_stdout_stderr_paths_and_sha256(tmpdir):
    """
    Verifies that benchmark runner persists real stdout and stderr evidence files,
    computes accurate cryptographic SHA-256 digests, and stores relative paths
    in the execution artifact and manifest.
    """
    suite = AegisBenchmarkSuite(artifacts_dir=Path(tmpdir))
    report = suite.run_benchmark(
        mode="smoke",
        baselines_to_run=["baseline_1"],
        save_results=True,
    )
    run_dir = Path(tmpdir) / report["run_id"]
    b1_dir = run_dir / "baseline_1"
    assert b1_dir.exists()

    json_files = list(b1_dir.glob("*.json"))
    assert len(json_files) > 0

    for jf in json_files:
        with open(jf, "r", encoding="utf-8") as f:
            art_data = json.load(f)

        assert "stdout_path" in art_data
        assert "stderr_path" in art_data
        assert "stdout_sha256" in art_data
        assert "stderr_sha256" in art_data

        stdout_p = Path(__file__).parent.parent / art_data["stdout_path"] if not Path(art_data["stdout_path"]).is_absolute() else Path(art_data["stdout_path"])
        if not stdout_p.exists():
            stdout_p = Path(jf.parent) / f"{jf.stem}_stdout.txt"
        assert stdout_p.exists(), f"Stdout file {stdout_p} does not exist"

        content = stdout_p.read_text(encoding="utf-8")
        computed_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert computed_sha == art_data["stdout_sha256"]


def test_modal_invocation_provenance_retention():
    """
    Verifies that Baseline 5 with Modal backend properly records all invocation provenance:
    remote app, functions invoked, execution stages, token provenance, and SHA-256 digests.
    """
    art = TargetExecutionArtifact(
        baseline_id="baseline_5",
        target_id="REENT-01",
        target_name="Vault",
        status=ExecutionStatus.SUCCESS,
        security_verdict="EXPLOIT_CONFIRMED",
        replay_status="CONFIRMED",
        persistence_status="persisted",
        process_exit_code=0,
        stdout_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        stderr_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        input_sha256="a1b2c3d4",
        output_sha256="d4c3b2a1",
        tool_metadata={
            "remote_backend": "modal",
            "modal_app": "aegis-rlvr-engine",
            "modal_functions": [
                "ProductionAuditAgent.generate_solidity_exploit",
                "verify_exploit_remote",
                "verify_replay_remote",
                "record_trajectory_remote"
            ],
            "remote_stages": {
                "inference": "remote_gpu",
                "sandbox": "remote_modal",
                "replay": "remote_modal",
                "persistence": "remote_volume",
            },
            "token_provenance": "remote_modal_h100",
            "cost_status": "unmeasured",
        }
    )
    d = art.to_dict()
    assert d["tool_metadata"]["remote_backend"] == "modal"
    assert "verify_exploit_remote" in d["tool_metadata"]["modal_functions"]
    assert d["tool_metadata"]["remote_stages"]["sandbox"] == "remote_modal"
    assert d["security_verdict"] == "EXPLOIT_CONFIRMED"
    assert d["replay_status"] == "CONFIRMED"
    assert d["persistence_status"] == "persisted"


def test_manifest_git_integrity_rejects_dirty_checkout():
    """
    Verifies that validate_manifest_git_integrity rejects runs where is_dirty=True
    when require_clean=True is specified (enforced during canonical real benchmark runs).
    """
    from benchmarks.protocol import validate_manifest_git_integrity, verify_manifest_git_integrity

    full_sha = "c1813a78c08952e34eb1afdac5b4cf5752547e79"
    run_dir = f"benchmarks/artifacts/run_1794146412_{full_sha[:7]}"

    manifest_dirty = {
        "run_id": f"run_1794146412_{full_sha[:7]}",
        "git": {"commit_sha": full_sha, "is_dirty": True, "branch": "feat/empirical-benchmark-runner"}
    }

    valid, err = validate_manifest_git_integrity(manifest_dirty, run_dir=run_dir, expected_commit_sha=full_sha, require_clean=True)
    assert valid is False
    assert "Dirty git checkout detected" in err

    with pytest.raises(ValueError, match="Dirty git checkout detected"):
        verify_manifest_git_integrity(manifest_dirty, run_dir=run_dir, expected_commit_sha=full_sha, require_clean=True)


def test_manifest_git_integrity_exact_sha_and_directory_suffix_matching():
    """
    Verifies that manifest validation enforces full 40-hex SHA format,
    rejects SHA mismatches against git checkout, and verifies run directory suffix.
    """
    from benchmarks.protocol import validate_manifest_git_integrity

    full_sha = "c1813a78c08952e34eb1afdac5b4cf5752547e79"
    mismatched_sha = "e2924b89d09063f45fc2befbd6c57f6863658f80"

    # 1. Reject non-hex or invalid length SHA
    short_manifest = {
        "run_id": "run_123_c1813a7",
        "git": {"commit_sha": "c1813a7", "is_dirty": False}
    }
    valid, err = validate_manifest_git_integrity(short_manifest)
    assert valid is False
    assert "40-character hexadecimal" in err

    # 2. Reject mismatch against expected checkout SHA
    manifest = {
        "run_id": f"run_123_{full_sha[:7]}",
        "git": {"commit_sha": full_sha, "is_dirty": False}
    }
    valid, err = validate_manifest_git_integrity(manifest, expected_commit_sha=mismatched_sha)
    assert valid is False
    assert "does not match expected checkout SHA" in err


def test_foundry_integration_cannot_pass_via_missing_binary_fallback_in_ci(monkeypatch):
    """
    Verifies that under CI environments (CI=true), live Foundry integration probe
    CANNOT silently pass or skip if forge binary is missing.
    """
    monkeypatch.setenv("FOUNDRY_CI", "true")
    monkeypatch.setattr(shutil, "which", lambda cmd: None if cmd == "forge" else shutil.which(cmd))

    with pytest.raises(AssertionError, match="Foundry binary 'forge' MUST be present on PATH in CI"):
        test_real_foundry_integration_live_execution()


def test_status_semantics_and_normalized_stage_outcomes():
    """
    Iteration 13 Blocker 4:
    Verifies that target execution artifacts and evaluation results clearly distinguish
    and normalize stage outcomes:
    - orchestration_status (pipeline status)
    - generation_outcome (CANDIDATE_GENERATED, GENERATION_FORMAT_ERROR, GENERATION_FAILED)
    - evm_outcome (BREACH_VERIFIED, SAFE_CONTROL_HELD, RUNTIME_REVERT, COMPILATION_ERROR, NOT_RUN)
    - security_verdict (EXPLOIT_CONFIRMED, RUNTIME_REVERT, SAFE_RUN, GENERATION_FORMAT_ERROR, COMPILATION_ERROR)
    - replay_status (CONFIRMED, NOT_ELIGIBLE, FAILED)
    - persistence_status (persisted, not_persisted, NOT_ELIGIBLE)
    """
    # 1. Successful exploit breach:
    art_exploit = TargetExecutionArtifact(
        baseline_id="baseline_5",
        target_id="REENT-01",
        target_name="Vault Solvency",
        status=ExecutionStatus.SUCCESS,
        detected=True,
        candidates_generated=1,
        verified_breaches=1,
        replayed_breaches=1,
        process_exit_code=0,
        security_verdict="EXPLOIT_CONFIRMED",
        replay_status="CONFIRMED",
        persistence_status="persisted",
        orchestration_status="COMPLETED",
        generation_outcome="CANDIDATE_GENERATED",
        evm_outcome="BREACH_VERIFIED",
    )
    d_exploit = art_exploit.to_dict()
    assert d_exploit["orchestration_status"] == "COMPLETED"
    assert d_exploit["generation_outcome"] == "CANDIDATE_GENERATED"
    assert d_exploit["evm_outcome"] == "BREACH_VERIFIED"
    assert d_exploit["security_verdict"] == "EXPLOIT_CONFIRMED"
    assert d_exploit["replay_status"] == "CONFIRMED"
    assert d_exploit["persistence_status"] == "persisted"

    # 2. Runtime revert:
    art_revert = TargetExecutionArtifact(
        baseline_id="baseline_5",
        target_id="BIZ-01",
        target_name="Business Logic",
        status=ExecutionStatus.SUCCESS,
        detected=False,
        candidates_generated=1,
        verified_breaches=0,
        replayed_breaches=0,
        process_exit_code=1,
        security_verdict="RUNTIME_REVERT",
        replay_status="NOT_ELIGIBLE",
        persistence_status="persisted",
        orchestration_status="COMPLETED",
        generation_outcome="CANDIDATE_GENERATED",
        evm_outcome="RUNTIME_REVERT",
    )
    d_revert = art_revert.to_dict()
    assert d_revert["generation_outcome"] == "CANDIDATE_GENERATED"
    assert d_revert["evm_outcome"] == "RUNTIME_REVERT"
    assert d_revert["security_verdict"] == "RUNTIME_REVERT"
    assert d_revert["replay_status"] == "NOT_ELIGIBLE"

    # 3. Generation format error:
    art_fmt = TargetExecutionArtifact(
        baseline_id="baseline_5",
        target_id="SIG-01",
        target_name="Signature Malleability",
        status=ExecutionStatus.SUCCESS,
        detected=False,
        candidates_generated=0,
        verified_breaches=0,
        replayed_breaches=0,
        process_exit_code=-4,
        security_verdict="GENERATION_FORMAT_ERROR",
        replay_status="NOT_ELIGIBLE",
        persistence_status="persisted",
        orchestration_status="COMPLETED",
        generation_outcome="GENERATION_FORMAT_ERROR",
        evm_outcome="NOT_RUN",
    )
    d_fmt = art_fmt.to_dict()
    assert d_fmt["generation_outcome"] == "GENERATION_FORMAT_ERROR"
    assert d_fmt["evm_outcome"] == "NOT_RUN"
    assert d_fmt["security_verdict"] == "GENERATION_FORMAT_ERROR"

    # 4. Safe control held:
    art_safe = TargetExecutionArtifact(
        baseline_id="baseline_5",
        target_id="SAFE-01",
        target_name="Safe Control Vault",
        status=ExecutionStatus.SUCCESS,
        detected=False,
        candidates_generated=1,
        verified_breaches=0,
        replayed_breaches=0,
        process_exit_code=1,
        security_verdict="SAFE_RUN",
        replay_status="NOT_ELIGIBLE",
        persistence_status="persisted",
        orchestration_status="COMPLETED",
        generation_outcome="CANDIDATE_GENERATED",
        evm_outcome="SAFE_CONTROL_HELD",
    )
    d_safe = art_safe.to_dict()
    assert d_safe["generation_outcome"] == "CANDIDATE_GENERATED"
    assert d_safe["evm_outcome"] == "SAFE_CONTROL_HELD"
    assert d_safe["security_verdict"] == "SAFE_RUN"

    # 5. Evaluator propagates all stage outcome fields into details
    gt = {
        "REENT-01": GroundTruth(contract_id="REENT-01", is_vulnerable=True),
        "BIZ-01": GroundTruth(contract_id="BIZ-01", is_vulnerable=True),
        "SIG-01": GroundTruth(contract_id="SIG-01", is_vulnerable=True),
        "SAFE-01": GroundTruth(contract_id="SAFE-01", is_vulnerable=False),
    }
    eval_res = evaluate_baseline_run("baseline_5", "Full Aegis-RLVR", [art_exploit, art_revert, art_fmt, art_safe], gt)
    assert eval_res.status == ExecutionStatus.SUCCESS
    detail_by_id = {row["target_id"]: row for row in eval_res.details}
    assert detail_by_id["REENT-01"]["orchestration_status"] == "COMPLETED"
    assert detail_by_id["REENT-01"]["generation_outcome"] == "CANDIDATE_GENERATED"
    assert detail_by_id["REENT-01"]["evm_outcome"] == "BREACH_VERIFIED"
    assert detail_by_id["SIG-01"]["generation_outcome"] == "GENERATION_FORMAT_ERROR"
    assert detail_by_id["SIG-01"]["evm_outcome"] == "NOT_RUN"
    assert detail_by_id["SAFE-01"]["evm_outcome"] == "SAFE_CONTROL_HELD"


def test_safe_control_sentinel_semantics_and_rejection_of_unrelated_failures():
    """
    Iteration 13 Blocker 4, hardened by Iteration 14 P0.4:
    Only the EXACT documented sentinel of the repository-owned harness, for the
    matching target/harness context, is accepted as proof of a safe control.
    Generic EVM reverts, compiler errors, panic codes, arbitrary
    'EXPLOIT_FAILED...' strings and empty reasons are rejected.
    """
    from benchmarks.protocol import validate_safe_control_sentinel_semantics
    from benchmarks.evidence_integrity import SAFE_CONTROL_SENTINELS

    # 1. The exact documented sentinel proves the safe control.
    valid, verdict = validate_safe_control_sentinel_semantics(
        SAFE_CONTROL_SENTINELS["SecureVault"], "NO_BREACH", "SecureVault"
    )
    assert valid is True
    assert verdict == "SAFE_RUN"

    valid, verdict = validate_safe_control_sentinel_semantics(
        SAFE_CONTROL_SENTINELS["SecureOraclePool"],
        "NO_BREACH",
        "SecureOraclePool",
        harness_suite="test/SecureOraclePoolHarness.t.sol",
    )
    assert valid is True
    assert verdict == "SAFE_RUN"

    # 2. A near-match (suffix) is NOT the documented sentinel.
    valid, reason = validate_safe_control_sentinel_semantics(
        SAFE_CONTROL_SENTINELS["SecureVault"] + " (Invariant balance >= deposit)",
        "NO_BREACH",
        "SecureVault",
    )
    assert valid is False
    assert "SENTINEL_SUFFIX_MISMATCH" in reason

    # 3. An arbitrary EXPLOIT_FAILED string is rejected (the old defect).
    valid, reason = validate_safe_control_sentinel_semantics(
        "EXPLOIT_FAILED: Safe control held", "NO_BREACH", "SecureVault"
    )
    assert valid is False
    assert reason.startswith(("SENTINEL_", "UNRECOGNIZED_"))

    # 4. Reject generic EVM revert
    valid, reason = validate_safe_control_sentinel_semantics(
        "EvmError: Revert", "NO_BREACH", "SecureVault"
    )
    assert valid is False
    assert "GENERIC_EVM_REVERT" in reason

    # 5. Reject EVM Panic codes (e.g. integer overflow, assert failure)
    valid, reason = validate_safe_control_sentinel_semantics(
        "Panic(0x11): Arithmetic underflow/overflow", "NO_BREACH", "SecureVault"
    )
    assert valid is False
    assert "EVM_PANIC" in reason

    # 6. Reject Solidity compilation errors
    valid, reason = validate_safe_control_sentinel_semantics(
        "Compiler run failed: ParserError: Expected ';' but got '}'", "NO_BREACH", "SecureVault"
    )
    assert valid is False
    assert "COMPILATION_ERROR" in reason

    # 7. Reject empty or None revert reasons
    valid, reason = validate_safe_control_sentinel_semantics(None)
    assert valid is False
    assert reason == "MISSING_REVERT_REASON"

    valid, reason = validate_safe_control_sentinel_semantics("")
    assert valid is False
    assert reason == "MISSING_REVERT_REASON"

    # 8. Without target context the sentinel cannot be attributed at all.
    valid, reason = validate_safe_control_sentinel_semantics(
        SAFE_CONTROL_SENTINELS["SecureVault"], "NO_BREACH"
    )
    assert valid is False
    assert reason == "MISSING_TARGET_CONTEXT_FOR_SENTINEL"


def test_replay_evidence_envelope_required_for_confirmed_status(tmp_path):
    """
    Iteration 13 Blocker 2, hardened by Iteration 14 P0.2:
    A replay may only be CONFIRMED when the envelope is complete AND every
    digest can be recomputed from the stored replay bytes.
    """
    from benchmarks.protocol import validate_replay_evidence_envelope
    from benchmarks.evidence_integrity import persist_replay_artifact, sha256_bytes

    stdout_bytes = b'{"status":"Success"}\n'
    candidate_bytes = b"contract ExploitModule { function runExploit() external payable {} }"
    harness_bytes = b"contract VaultHarness {}\n"

    stdout_art = persist_replay_artifact(tmp_path, "REENT-01_replay_stdout.txt", stdout_bytes)
    stderr_art = persist_replay_artifact(tmp_path, "REENT-01_replay_stderr.txt", b"")
    candidate_art = persist_replay_artifact(tmp_path, "REENT-01_replay_candidate.sol", candidate_bytes)
    harness_art = persist_replay_artifact(tmp_path, "REENT-01_replay_harness.t.sol", harness_bytes)

    valid_envelope = {
        "reproduced": True,
        "container_id": "hokkglpxczflmxlcnxxg",
        "command": "forge test --offline --json -vvvv",
        "argv": ["forge", "test", "--offline", "--json", "-vvvv"],
        "exit_code": 0,
        "return_code": 0,
        "invariant_violated": True,
        "harness_verdict": "BREACH",
        "stdout_artifact": stdout_art.to_dict(),
        "stderr_artifact": stderr_art.to_dict(),
        "candidate_input_artifact": candidate_art.to_dict(),
        "harness_input_artifact": harness_art.to_dict(),
        "stdout_sha256": stdout_art.sha256,
        "stderr_sha256": stderr_art.sha256,
        "candidate_sha256": candidate_art.sha256,
        "harness_sha256": harness_art.sha256,
        "utc_start_time": "2026-11-09T03:17:41Z",
        "utc_end_time": "2026-11-09T03:19:20Z",
    }

    valid_art = {
        "target_id": "REENT-01",
        "replay_status": "CONFIRMED",
        "replayed_breaches": 1,
        "replay_evidence": valid_envelope,
        "utc_start_time": "2026-11-09T02:00:00Z",
        "utc_end_time": "2026-11-09T02:05:00Z",
        "output_sha256": candidate_art.sha256,
    }

    # 1. Valid envelope passes
    is_valid, err = validate_replay_evidence_envelope(valid_art, artifact_root=tmp_path)
    assert is_valid is True
    assert err is None

    # 2. Missing envelope fails
    missing_env_art = {"target_id": "REENT-01", "replay_status": "CONFIRMED", "replayed_breaches": 1}
    is_valid, err = validate_replay_evidence_envelope(missing_env_art, artifact_root=tmp_path)
    assert is_valid is False
    assert "missing or empty" in err

    # 3. Non-zero exit code fails
    nonzero_env = dict(valid_envelope, exit_code=1)
    is_valid, err = validate_replay_evidence_envelope(
        {"replay_status": "CONFIRMED", "replayed_breaches": 1, "replay_evidence": nonzero_env},
        artifact_root=tmp_path,
    )
    assert is_valid is False
    assert "exit_code must be the integer 0" in err

    # 4. Missing container ID fails
    no_container_env = dict(valid_envelope, container_id="")
    is_valid, err = validate_replay_evidence_envelope(
        {"replay_status": "CONFIRMED", "replayed_breaches": 1, "replay_evidence": no_container_env},
        artifact_root=tmp_path,
    )
    assert is_valid is False
    assert "container" in err

    # 5. A synthetic container identity fails
    synthetic_env = dict(valid_envelope, container_id="modal-cpu-ca9285db97bf")
    is_valid, err = validate_replay_evidence_envelope(
        {"replay_status": "CONFIRMED", "replayed_breaches": 1, "replay_evidence": synthetic_env},
        artifact_root=tmp_path,
    )
    assert is_valid is False
    assert "synthetic container id" in err

    # 6. A digest that does not describe the stored bytes fails
    bad_hash_env = dict(valid_envelope)
    bad_hash_env["stdout_artifact"] = dict(
        stdout_art.to_dict(), sha256=sha256_bytes(b"tampered")
    )
    is_valid, err = validate_replay_evidence_envelope(
        {"replay_status": "CONFIRMED", "replayed_breaches": 1, "replay_evidence": bad_hash_env},
        artifact_root=tmp_path,
    )
    assert is_valid is False
    assert "does not match the recomputed digest" in err

    # 7. Reusing the initial run's timestamps fails
    reused_ts_env = dict(
        valid_envelope,
        utc_start_time="2026-11-09T02:00:00Z",
        utc_end_time="2026-11-09T02:05:00Z",
    )
    is_valid, err = validate_replay_evidence_envelope(
        {
            "replay_status": "CONFIRMED",
            "replayed_breaches": 1,
            "replay_evidence": reused_ts_env,
            "utc_start_time": "2026-11-09T02:00:00Z",
            "utc_end_time": "2026-11-09T02:05:00Z",
        },
        artifact_root=tmp_path,
    )
    assert is_valid is False
    assert "initial run" in err

    # 8. reproduced=False fails
    not_reproduced_env = dict(valid_envelope, reproduced=False)
    is_valid, err = validate_replay_evidence_envelope(
        {"replay_status": "CONFIRMED", "replayed_breaches": 1, "replay_evidence": not_reproduced_env},
        artifact_root=tmp_path,
    )
    assert is_valid is False
    assert "reproduction" in err

    # 9. Without the stored artifacts the envelope can never be confirmed.
    is_valid, err = validate_replay_evidence_envelope(valid_art)
    assert is_valid is False
    assert "artifact root" in err

    # 10. Non-confirmed replay status does not require envelope
    unreplayed_art = {"target_id": "BIZ-01", "replay_status": "NOT_ELIGIBLE", "replayed_breaches": 0}
    is_valid, err = validate_replay_evidence_envelope(unreplayed_art, artifact_root=tmp_path)
    assert is_valid is True


def test_manifest_rejects_missing_remote_toolchain_provenance():
    """
    Iteration 13 Blocker 3, hardened by Iteration 14 P0.3:
    The remote EVM provenance must consist of observed facts only, must name
    the immutable image digest and must never carry a hardcoded constant.
    """
    from benchmarks.protocol import validate_remote_evm_toolchain_provenance
    from benchmarks.evidence_integrity import observed, not_available

    valid_toolchain = {
        "remote_os": observed("Debian GNU/Linux 12 (bookworm)", source="/etc/os-release:PRETTY_NAME"),
        "remote_platform": observed("posix", source="os.name"),
        "image_digest": observed("im-9QaB3xKd7Lm2Np", source="modal.config.image_id"),
        "forge_version": observed(
            "forge Version: 1.9.0\nCommit SHA: 6056c5845d34205a83cf7108042adb137325c9df",
            source="forge --version",
        ),
        "solc_versions": observed(["0.8.20"], source="forge config --json:solc"),
        "exact_forge_argv": observed(
            ["forge", "test", "--offline", "--json", "-vvvv"], source="the argv that was executed"
        ),
        "working_directory": observed("/tmp/tmpab12cd", source="the cwd of the forge process"),
        "compiler_settings": observed(
            {"evm_version": "shanghai", "optimizer": True, "optimizer_runs": 200, "via_ir": False},
            source="forge config --json",
        ),
        "observed_exit_code": observed(0, source="the exit code of the forge process"),
    }

    # 1. Valid toolchain provenance passes
    art_with_toolchain = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": valid_toolchain,
    }
    is_valid, err = validate_remote_evm_toolchain_provenance(art_with_toolchain)
    assert is_valid is True
    assert err is None

    # 2. EVM ran but provenance is missing -> fails
    art_missing_toolchain = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": None,
    }
    is_valid, err = validate_remote_evm_toolchain_provenance(art_missing_toolchain)
    assert is_valid is False
    assert "Missing remote_evm_provenance" in err

    # 3. Missing required field (e.g. forge_version) -> fails
    incomplete_toolchain = dict(valid_toolchain, forge_version="")
    art_incomplete = {
        "target_id": "BIZ-01",
        "evm_outcome": "RUNTIME_REVERT",
        "security_verdict": "RUNTIME_REVERT",
        "process_exit_code": 1,
        "remote_evm_provenance": incomplete_toolchain,
    }
    is_valid, err = validate_remote_evm_toolchain_provenance(art_incomplete)
    assert is_valid is False
    assert "forge_version" in err

    # 4. A hardcoded constant is rejected even when it is present.
    hardcoded_toolchain = dict(
        valid_toolchain,
        working_directory=observed(
            "/tmp/aegis_sandbox", source="the cwd of the forge process"
        ),
    )
    art_hardcoded = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": hardcoded_toolchain,
    }
    is_valid, err = validate_remote_evm_toolchain_provenance(art_hardcoded)
    assert is_valid is False
    assert "legacy hardcoded constant" in err

    # 5. An explicit NOT_AVAILABLE with a reason is accepted.
    unavailable_toolchain = dict(
        valid_toolchain,
        image_digest=not_available("the Modal runtime did not expose an image id"),
    )
    art_unavailable = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": unavailable_toolchain,
    }
    is_valid, err = validate_remote_evm_toolchain_provenance(art_unavailable)
    assert is_valid is True
    assert err is None

    # 6. EVM did NOT run (format error before EVM) -> correctly skipped
    art_not_run = {
        "target_id": "SIG-01",
        "evm_outcome": "NOT_RUN",
        "security_verdict": "GENERATION_FORMAT_ERROR",
        "process_exit_code": -4,
    }
    is_valid, err = validate_remote_evm_toolchain_provenance(art_not_run)
    assert is_valid is True


def test_modal_billing_reconciliation_integrity():
    """
    Iteration 14 Requirement 1, expressed against the authoritative API.

    The upstream line (7876f6e) shipped a billing reconciliation validator
    together with five negative cases. This branch keeps the stricter
    iteration-line validator (benchmarks.evidence_integrity), so the upstream
    coverage is ported onto that API instead of being dropped together with
    the conflicting file:

    1. the published join table reconciles exactly with the raw export;
    2. a target-level cost without a proven invocation-level join is rejected;
    3. a raw billing line item that is accounted for twice is rejected;
    4. a manufactured 'modal-app://' pseudo-URI is detected;
    5. a raw billing line item that is not accounted for at all is rejected.
    """
    from benchmarks.evidence_integrity import (
        has_synthetic_modal_uri,
        load_raw_billing_line_items,
        validate_billing_attribution,
    )

    root = Path(__file__).parent.parent
    raw_path = root / "benchmarks" / "evidence" / "modal_billing_report_raw.json"
    join_path = root / "benchmarks" / "evidence" / "modal_billing_join_table.json"

    assert raw_path.is_file(), "the raw billing export must exist"
    assert join_path.is_file(), "the billing join table must exist"

    items = load_raw_billing_line_items(raw_path)
    join_table = json.loads(join_path.read_text(encoding="utf-8"))
    known_app_ids = [item.object_id for item in items]

    # 1. The published join table reconciles exactly with the raw export.
    is_valid, err = validate_billing_attribution(
        join_table, items, known_app_ids=known_app_ids
    )
    assert is_valid is True, f"billing reconciliation failed: {err}"
    assert err is None

    # 2. A target-level cost without a proven invocation-level join is rejected.
    bad_cost_join = json.loads(json.dumps(join_table))
    bad_cost_join["target_level"][0]["cost_usd"] = 0.05
    bad_cost_join["target_level"][0]["cost_usd_exact"] = "0.05"
    is_valid, err = validate_billing_attribution(
        bad_cost_join, items, known_app_ids=known_app_ids
    )
    assert is_valid is False
    assert "without a proven invocation-level join" in err

    # 3. A raw billing line item that is accounted for twice is rejected.
    bad_item_join = json.loads(json.dumps(join_table))
    first_row = bad_item_join["app_session_level"][0]
    second_row = bad_item_join["app_session_level"][1]
    second_row["line_item_keys"] = list(second_row["line_item_keys"]) + list(
        first_row["line_item_keys"]
    )
    is_valid, err = validate_billing_attribution(
        bad_item_join, items, known_app_ids=known_app_ids
    )
    assert is_valid is False
    assert "double-counts at least one raw billing line item" in err

    # 4. A manufactured modal-app:// pseudo-URI is detected.
    bad_uri_join = json.loads(json.dumps(join_table))
    bad_uri_join["target_level"][0]["durable_log_ref"] = "modal-app://logs/app-123"
    assert has_synthetic_modal_uri(bad_uri_join) is True
    assert has_synthetic_modal_uri(join_table) is False

    # 5a. A raw billing line item that is not accounted for at all is rejected.
    incomplete_join = json.loads(json.dumps(join_table))
    dropped_row = incomplete_join["app_session_level"].pop()
    is_valid, err = validate_billing_attribution(
        incomplete_join, items, known_app_ids=known_app_ids
    )
    assert is_valid is False
    assert "omits" in err
    assert dropped_row["line_item_keys"]

    # 5b. A raw billing line item the attribution does not know is rejected.
    is_valid, err = validate_billing_attribution(
        join_table,
        items[:-1],
        known_app_ids=[item.object_id for item in items[:-1]],
    )
    assert is_valid is False
    assert "references unknown line item" in err


def test_baseline5_api_path_uses_real_hypothesis_manager(monkeypatch):
    """The API-backed Baseline 5 path must use the existing hypothesis manager."""
    from core.hypothesis_manager import HypothesisManager
    from core.schemas import TargetProgram

    target = TargetProgram(
        name="AccessControlVault",
        source_code="contract AccessControlVault { function setOwner(address) external {} }",
        invariants=["Only the current owner may change ownership"],
        slither_findings=[{
            "check": "unprotected-setowner",
            "impact": "High",
            "description": "Access control is missing from setOwner",
            "function": "setOwner",
        }],
    )
    manager = HypothesisManager(target)
    hypotheses = manager.ingest_slither_findings()

    assert hypotheses
    converted = manager.to_attack_hypothesis(hypotheses[0])
    assert converted.vulnerability_type == "AccessControl"
    assert "setOwner" in converted.affected_functions
