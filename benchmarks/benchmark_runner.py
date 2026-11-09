"""
benchmarks/benchmark_runner.py

Aegis-RLVR Multi-Baseline Benchmark Runner.
Executes and evaluates vulnerability detection and exploit verification accuracy across 5 distinct paradigms:
1. Baseline 1: Static Analysis Only (Slither AST / taint analysis)
2. Baseline 2: LLM Auditor Only (Zero-shot text vulnerability audit findings)
3. Baseline 3: LLM Auditor + LLM Exploit Generation (Unverified PoC synthesis)
4. Baseline 4: LLM Auditor + Exploit Generation + Naive Foundry (Text marker / Exit code 0)
5. Baseline 5: Full Aegis-RLVR (Hypothesis Pipeline + Isolated Runner + Trusted State Oracle + Independent Replay)

Enforces:
- Strict protocol separation: Baseline adapters receive ONLY public TargetSpecification (zero ground truth leakage).
- Ground truth is reserved strictly for post-run evaluation of confusion matrices.
- Dynamic candidate counts derived from real generator outputs (no hardcoded constants).
- Fail-closed execution: missing tools or credentials produce explicit UNAVAILABLE/INCOMPLETE statuses,
  never fabricated 0% or 100% metrics.
- Machine-readable JSON execution artifacts saved per target and per baseline with full provenance.
- Clear distinction between synthetic smoke tests (--mode smoke) and real experiments (--mode real).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
_ROOT = Path(__file__).parent.parent.resolve()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Any, Optional

from core.schemas import TargetProgram
from benchmarks.protocol import (
    BenchmarkDataset,
    TargetSpecification,
    GroundTruth,
    TargetExecutionArtifact,
    BaselineEvaluationResult,
    ExecutionStatus,
    RunReproducibilityManifest,
    GitManifest,
    EnvironmentManifest,
    DatasetManifest,
    AdapterRunManifest,
    ArtifactFileRecord,
    validate_manifest_git_integrity,
    verify_manifest_git_integrity,
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
    ensure_modal_app_context,
)


@dataclass
class BaselineMetrics:
    """
    Backward-compatible metrics container.
    Retained for existing test suites and derived metrics validation.
    """
    baseline_id: str
    baseline_name: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    exploit_success_rate: float = 0.0
    verified_finding_rate: float = 0.0
    replay_reproducibility_rate: float = 0.0
    candidates_per_verified_finding: float = 0.0
    average_duration_seconds: float = 0.0
    estimated_cost_usd_per_target: float = 0.0
    details: List[Dict[str, Any]] = field(default_factory=list)

    def calculate_derived_metrics(self, total_candidates: int, total_verified: int, total_replayed: int):
        total_p = self.true_positives + self.false_positives
        total_actual_p = self.true_positives + self.false_negatives
        total_actual_n = self.true_negatives + self.false_positives

        self.precision = round(self.true_positives / total_p, 4) if total_p > 0 else 0.0
        self.recall = round(self.true_positives / total_actual_p, 4) if total_actual_p > 0 else 0.0

        if (self.precision + self.recall) > 0:
            self.f1_score = round(2 * (self.precision * self.recall) / (self.precision + self.recall), 4)
        else:
            self.f1_score = 0.0

        self.false_positive_rate = round(self.false_positives / total_actual_n, 4) if total_actual_n > 0 else 0.0
        self.false_negative_rate = round(self.false_negatives / total_actual_p, 4) if total_actual_p > 0 else 0.0

        self.verified_finding_rate = round(total_verified / total_actual_p, 4) if total_actual_p > 0 else 0.0
        self.exploit_success_rate = round(total_verified / total_candidates, 4) if total_candidates > 0 else 0.0
        self.replay_reproducibility_rate = round(total_replayed / total_verified, 4) if total_verified > 0 else 0.0

        if total_verified > 0:
            self.candidates_per_verified_finding = round(total_candidates / total_verified, 2)
        else:
            self.candidates_per_verified_finding = float("inf")


class AegisBenchmarkSuite:
    def __init__(
        self,
        dataset_path: Optional[Path] = None,
        artifacts_dir: Optional[Path] = None
    ):
        if dataset_path is None:
            dataset_path = Path(__file__).parent / "benchmark_dataset.json"
        self.dataset_path = Path(dataset_path).resolve()
        self.dataset = BenchmarkDataset(self.dataset_path)

        if artifacts_dir is None:
            artifacts_dir = Path(__file__).parent / "artifacts"
        self.artifacts_base_dir = Path(artifacts_dir).resolve()

    def get_all_targets(self) -> List[Dict[str, Any]]:
        """Legacy helper returning raw dictionary representation of all targets."""
        targets = []
        for c in self.dataset.raw_data.get("classes", []):
            targets.extend(c.get("targets", []))
        for ctrl in self.dataset.raw_data.get("synthetic_controls", []):
            targets.append(ctrl)
        return targets

    def _get_git_commit_sha(self) -> str:
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True, cwd=str(self.dataset_path.parent)
            ).strip()
        except Exception:
            return "unknown"

    def _get_git_manifest(self) -> GitManifest:
        commit_sha = self._get_git_commit_sha()
        is_dirty = False
        branch = "unknown"
        try:
            status_out = subprocess.check_output(
                ["git", "status", "--porcelain"], text=True, cwd=str(self.dataset_path.parent)
            ).strip()
            is_dirty = bool(status_out)
            branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True, cwd=str(self.dataset_path.parent)
            ).strip()
        except Exception:
            pass
        return GitManifest(commit_sha=commit_sha, is_dirty=is_dirty, branch=branch)

    def _get_environment_manifest(self) -> EnvironmentManifest:
        python_ver = sys.version.split()[0]
        os_plat = sys.platform

        slither_ver = None
        if shutil.which("slither"):
            slither_ver = SlitherBaselineAdapter().get_slither_version()

        forge_ver = None
        if shutil.which("forge"):
            forge_ver = LLMNaiveFoundryBaselineAdapter().get_forge_version()

        solc_ver = None
        if shutil.which("solc"):
            try:
                res = subprocess.run(["solc", "--version"], stdout=subprocess.PIPE, text=True, timeout=5)
                solc_ver = res.stdout.strip().split("\n")[-1] or None
            except Exception:
                pass

        modal_ver = None
        modal_auth = False
        try:
            import modal
            modal_ver = getattr(modal, "__version__", None)
            modal_auth = bool(modal.config.config.get("token_id"))
        except Exception:
            pass

        package_versions: Dict[str, str] = {}
        for pkg_name in ("pydantic", "torch", "pytest", "google-genai", "openai", "slither-analyzer"):
            try:
                import importlib.metadata
                package_versions[pkg_name] = importlib.metadata.version(pkg_name)
            except Exception:
                pass

        provider_configs: Dict[str, Dict[str, Any]] = {
            "gemini": {
                "available": bool(os.environ.get("GEMINI_API_KEY")),
            },
            "openai": {
                "available": bool(os.environ.get("OPENAI_API_KEY")),
            },
        }

        remote_evm_environment = {
            "remote_os": "Debian GNU/Linux 12 (bookworm)",
            "remote_platform": "linux",
            "image_tag": "debian:12-slim-foundry",
            "forge_version": "forge 1.9.5 (92f59f6 2026-11-04T00:23:44.821105000Z)",
            "solc_versions": ["0.8.20", "0.8.24"],
            "exact_forge_argv": ["forge", "test", "--offline", "--json", "-vvvv"],
            "working_directory": "/tmp/aegis_sandbox",
            "compiler_settings": {
                "evm_version": "paris",
                "optimizer": True,
                "optimizer_runs": 200,
                "via_ir": False,
            },
        }

        return EnvironmentManifest(
            python_version=python_ver,
            os_platform=os_plat,
            slither_version=slither_ver,
            forge_version=forge_ver,
            solc_version=solc_ver,
            modal_version=modal_ver,
            modal_authenticated=modal_auth,
            package_versions=package_versions,
            provider_configs=provider_configs,
            remote_evm_environment=remote_evm_environment,
        )

    def _get_dataset_manifest(self, public_targets: List[TargetSpecification]) -> DatasetManifest:
        d_sha = ""
        try:
            d_sha = hashlib.sha256(self.dataset_path.read_bytes()).hexdigest()
        except Exception:
            pass
        return DatasetManifest(
            version=self.dataset.version,
            dataset_sha256=d_sha,
            target_count=len(public_targets),
            target_ids=[t.contract_id for t in public_targets],
        )

    def run_benchmark(
        self,
        mode: str = "smoke",
        model_id: str = "gemini-1.5-pro",
        provider: str = "gemini",
        save_results: bool = True,
        baselines_to_run: Optional[List[str]] = None,
        custom_adapters: Optional[Dict[str, BaselineAdapter]] = None,
        baseline5_provider: Optional[str] = None,
        baseline5_model_id: Optional[str] = None,
        require_clean: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Executes the benchmark suite across baselines.

        Args:
            mode: "smoke" for fast synthetic CI verification; "real" for live tool execution.
            model_id: Model identifier for LLM-based baselines (Baselines 2-4, and default for 5).
            provider: LLM provider name ("gemini" or "openai") for Baselines 2-4.
            save_results: Whether to persist benchmark_results.json and per-target JSON artifacts.
            baselines_to_run: Optional list of baseline_ids to filter (e.g. ["baseline_1", "baseline_5"]).
            custom_adapters: Optional dictionary of adapter overrides (useful for testing).
            baseline5_provider: Dedicated inference backend for Baseline 5 (Full Aegis-RLVR).
                                Choices: "modal_h100", "modal_t4", "gemini", "openai".
                                Defaults to `provider` if None.
            baseline5_model_id: Model ID override for Baseline 5 (e.g. "qtum/Qwen3-Coder-30B-A3B-Audit").
        """
        if mode not in ("smoke", "real"):
            raise ValueError("mode must be 'smoke' or 'real'")

        # Resolve Baseline 5 provider & model
        b5_provider = baseline5_provider if baseline5_provider is not None else provider
        b5_model_id = baseline5_model_id if baseline5_model_id is not None else model_id

        # Validate Baseline 5 provider
        valid_b5_providers = ("gemini", "openai", "modal_h100", "modal_t4")
        if b5_provider not in valid_b5_providers:
            raise ValueError(
                f"Invalid Baseline 5 provider '{b5_provider}'. "
                f"Supported providers for Baseline 5 are: {', '.join(valid_b5_providers)}"
            )

        # Validate Baselines 2-4 provider
        valid_llm_providers = ("gemini", "openai")
        active_baselines = baselines_to_run if baselines_to_run else ["baseline_1", "baseline_2", "baseline_3", "baseline_4", "baseline_5"]
        llm_baselines_active = any(b in ("baseline_2", "baseline_3", "baseline_4") for b in active_baselines)
        if llm_baselines_active and provider not in valid_llm_providers:
            raise ValueError(
                f"Invalid provider '{provider}' for Baselines 2-4. "
                f"Baselines 2-4 require an LLM API provider ({', '.join(valid_llm_providers)}). "
                f"To configure Baseline 5 with a dedicated Modal GPU backend without affecting Baselines 2-4, "
                f"use --provider gemini (or openai) and --baseline5-provider {b5_provider}."
            )

        # Default model ID resolution for Modal GPU tiers
        from core.config import PipelineConfig
        if b5_provider == "modal_h100" and (baseline5_model_id is None and (b5_model_id is None or b5_model_id == model_id)):
            b5_model_id = PipelineConfig.AUDIT_GPU_MODEL
        elif b5_provider == "modal_t4" and (baseline5_model_id is None and (b5_model_id is None or b5_model_id == model_id)):
            b5_model_id = PipelineConfig.DEV_GPU_MODEL

        suite_start_time = time.time()
        commit_sha = self._get_git_commit_sha()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
        run_id = f"run_{int(time.time())}_{commit_sha[:7]}"

        public_targets = self.dataset.get_public_targets()
        ground_truth_map = self.dataset.get_ground_truth()

        # Build adapters
        adapters: Dict[str, BaselineAdapter] = {}
        if custom_adapters:
            adapters = dict(custom_adapters)
        elif mode == "smoke":
            adapters = {
                "baseline_1": SyntheticSmokeAdapter("baseline_1", "Static Analysis Only (Slither)"),
                "baseline_2": SyntheticSmokeAdapter("baseline_2", "LLM Auditor Only (Raw Text Findings)"),
                "baseline_3": SyntheticSmokeAdapter("baseline_3", "LLM Auditor + Exploit Gen (Unverified PoC)"),
                "baseline_4": SyntheticSmokeAdapter("baseline_4", "LLM + Naive Foundry (Exit Code 0 / Text Marker)"),
                "baseline_5": SyntheticSmokeAdapter("baseline_5", f"Full Aegis-RLVR ({b5_provider})"),
            }
        else:  # mode == "real"
            adapters = {
                "baseline_1": SlitherBaselineAdapter(),
                "baseline_2": LLMAuditorBaselineAdapter(model_id=model_id, provider=provider),
                "baseline_3": LLMUnverifiedPoCBaselineAdapter(model_id=model_id, provider=provider),
                "baseline_4": LLMNaiveFoundryBaselineAdapter(model_id=model_id, provider=provider),
                "baseline_5": FullAegisRLVRBaselineAdapter(model_id=b5_model_id, provider=b5_provider),
            }

        if baselines_to_run:
            adapters = {k: v for k, v in adapters.items() if k in baselines_to_run}

        run_artifacts_dir = self.artifacts_base_dir / run_id
        if save_results:
            run_artifacts_dir.mkdir(parents=True, exist_ok=True)

        results: Dict[str, Dict[str, Any]] = {}
        adapter_manifests: Dict[str, AdapterRunManifest] = {}
        base_dir = self.dataset_path.parent.parent

        from contextlib import nullcontext

        needs_modal = any(
            isinstance(ad, FullAegisRLVRBaselineAdapter) and getattr(ad, "provider", "") in ("modal_h100", "modal_t4")
            for ad in adapters.values()
        )
        app_ctx = ensure_modal_app_context() if needs_modal else nullcontext()

        with app_ctx:
            for b_id, adapter in adapters.items():
                baseline_start_time = time.time()
                baseline_artifacts: List[TargetExecutionArtifact] = []
                adapter_artifact_files: List[ArtifactFileRecord] = []
    
                # Create baseline artifact directory
                if save_results:
                    b_dir = run_artifacts_dir / b_id
                    b_dir.mkdir(parents=True, exist_ok=True)
    
                for target in public_targets:
                    # Adapters receive ONLY public TargetSpecification (zero ground-truth leakage)
                    artifact = adapter.execute_target(target, base_dir=base_dir)
                    baseline_artifacts.append(artifact)
    
                    # Save per-target JSON artifact and stdout/stderr evidence
                    if save_results:
                        stdout_content = ""
                        stderr_content = ""
                        if isinstance(artifact.raw_output, dict):
                            stdout_content = str(artifact.raw_output.get("stdout") or "")
                            stderr_content = str(artifact.raw_output.get("stderr") or "")
                        elif isinstance(artifact.logs, list) and artifact.logs:
                            stderr_content = "\n".join(str(l) for l in artifact.logs)
    
                        stdout_file = run_artifacts_dir / b_id / f"{target.contract_id}_stdout.txt"
                        stderr_file = run_artifacts_dir / b_id / f"{target.contract_id}_stderr.txt"
                        stdout_file.write_text(stdout_content, encoding="utf-8")
                        stderr_file.write_text(stderr_content, encoding="utf-8")
    
                        try:
                            rel_stdout_path = str(stdout_file.relative_to(base_dir)).replace("\\", "/")
                        except ValueError:
                            rel_stdout_path = f"{run_id}/{b_id}/{stdout_file.name}"
    
                        try:
                            rel_stderr_path = str(stderr_file.relative_to(base_dir)).replace("\\", "/")
                        except ValueError:
                            rel_stderr_path = f"{run_id}/{b_id}/{stderr_file.name}"
    
                        artifact.stdout_path = rel_stdout_path
                        artifact.stderr_path = rel_stderr_path
                        if not artifact.stdout_sha256:
                            artifact.stdout_sha256 = hashlib.sha256(stdout_content.encode("utf-8")).hexdigest()
                        if not artifact.stderr_sha256:
                            artifact.stderr_sha256 = hashlib.sha256(stderr_content.encode("utf-8")).hexdigest()
    
                        if not artifact.security_verdict:
                            if artifact.status == ExecutionStatus.UNAVAILABLE:
                                artifact.security_verdict = "UNAVAILABLE"
                            elif artifact.status == ExecutionStatus.FAILED:
                                artifact.security_verdict = "EXECUTION_FAILURE"
                            elif artifact.detected:
                                artifact.security_verdict = "DETECTED_POTENTIAL_VULNERABILITY"
                            else:
                                artifact.security_verdict = "NO_BREACH"
    
                        if not artifact.replay_status:
                            artifact.replay_status = "NOT_ELIGIBLE"
                        if not artifact.persistence_status:
                            artifact.persistence_status = "NOT_ELIGIBLE"
    
                        art_file = run_artifacts_dir / b_id / f"{target.contract_id}.json"
                        art_dict = artifact.to_dict()
                        with open(art_file, "w", encoding="utf-8") as f:
                            json.dump(art_dict, f, indent=2)
    
    
    
                        # Track file provenance with cryptographic hash and byte size
                        try:
                            art_bytes = art_file.read_bytes()
                            art_sha = hashlib.sha256(art_bytes).hexdigest()
                            try:
                                rel_art_path = str(art_file.relative_to(base_dir)).replace("\\", "/")
                            except ValueError:
                                try:
                                    rel_art_path = str(art_file.relative_to(self.artifacts_base_dir)).replace("\\", "/")
                                except ValueError:
                                    rel_art_path = f"{run_id}/{b_id}/{art_file.name}"
    
                            adapter_artifact_files.append(
                                ArtifactFileRecord(
                                    relative_path=rel_art_path,
                                    size_bytes=len(art_bytes),
                                    sha256=art_sha,
                                )
                            )
                        except Exception as err:
                            pass
    
                # Post-run evaluation consuming artifacts and private GroundTruth
                eval_result: BaselineEvaluationResult = evaluate_baseline_run(
                    baseline_id=b_id,
                    baseline_name=adapter.baseline_name,
                    artifacts=baseline_artifacts,
                    ground_truth_map=ground_truth_map,
                )
                results[b_id] = eval_result.to_dict()
    
                # Build per-adapter execution manifest derived directly from actual execution records
                is_avail, avail_reason = adapter.check_availability()
                adapter_duration = round(time.time() - baseline_start_time, 3)
    
                # Planned command/argv, timeout, resource budget, and config hash (template/intent)
                default_argv = adapter.get_default_argv()
                planned_argv = list(default_argv) if default_argv else None
                planned_cmd = " ".join(planned_argv) if planned_argv else None
                planned_timeout_sec = adapter.timeout_sec
                planned_resource_budget = dict(adapter.resource_budget) if adapter.resource_budget else {}
                planned_config_hash = adapter.get_effective_config_hash()
    
                # Adapter-level actual execution evidence:
                # Per Issue #10 Section 7 & reviewer acceptance criteria:
                # An adapter executes multiple distinct targets with distinct paths and argvs.
                # Adapter-level actual argv and command are strictly None.
                # Adapter-level actual timeout_sec, resource_budget, and config_hash must be derived strictly
                # from actual invocation records. If zero targets were invoked, or if targets have mixed/differing
                # values, adapter-level actual fields remain None / empty, keeping exact values exclusively
                # in per_target_provenance.
                actual_adapter_argv = None
                actual_adapter_cmd = None
    
                invoked_artifacts = [
                    art for art in baseline_artifacts
                    if art.status != ExecutionStatus.UNAVAILABLE
                    and art.timeout_sec is not None
                    and (art.argv is not None or art.tool_metadata.get("provider") is not None)
                ]
    
                actual_timeout_sec: Optional[int] = None
                actual_resource_budget: Dict[str, Any] = {}
                actual_config_hash: Optional[str] = None
    
                if len(baseline_artifacts) > 0 and len(invoked_artifacts) == len(baseline_artifacts):
                    # Check timeouts
                    invoked_timeouts = {art.timeout_sec for art in invoked_artifacts if art.timeout_sec is not None}
                    if len(invoked_timeouts) == 1 and all(art.timeout_sec is not None for art in invoked_artifacts):
                        actual_timeout_sec = next(iter(invoked_timeouts))
    
                    # Check resource budgets
                    invoked_budgets = [dict(art.resource_budget) for art in invoked_artifacts if art.resource_budget]
                    if len(invoked_budgets) == len(invoked_artifacts) and all(b == invoked_budgets[0] for b in invoked_budgets):
                        actual_resource_budget = dict(invoked_budgets[0])
    
                    # Check config hashes
                    invoked_hashes = {art.effective_config_hash for art in invoked_artifacts if art.effective_config_hash is not None}
                    if len(invoked_hashes) == 1 and all(art.effective_config_hash is not None for art in invoked_artifacts):
                        actual_config_hash = next(iter(invoked_hashes))
    
                per_target_provenance: Dict[str, Dict[str, Any]] = {}
                for art in baseline_artifacts:
                    # P1-A: Explicit key presence and None handling for exit code (preserves integer 0)
                    target_exit_code = None
                    if art.process_exit_code is not None:
                        target_exit_code = int(art.process_exit_code)
                    elif "exit_code" in art.tool_metadata and art.tool_metadata["exit_code"] is not None:
                        target_exit_code = int(art.tool_metadata["exit_code"])
                    elif "forge_exit_code" in art.tool_metadata and art.tool_metadata["forge_exit_code"] is not None:
                        target_exit_code = int(art.tool_metadata["forge_exit_code"])
    
                    # P1-B: Actual argv / command comes ONLY from invocation artifact; null if uninvoked
                    if art.argv is not None:
                        actual_art_argv = list(art.argv)
                        actual_art_cmd = " ".join(actual_art_argv)
                    else:
                        actual_art_argv = None
                        actual_art_cmd = None
    
                    provider_name = art.tool_metadata.get("provider")
                    model_id = art.tool_metadata.get("model_id")
    
                    per_target_provenance[art.target_id] = {
                        "target_name": art.target_name,
                        "status": art.status.value,
                        "unavailable_reason": art.unavailable_reason,
                        "argv": actual_art_argv,
                        "command": actual_art_cmd,
                        "provider": provider_name,
                        "model_id": model_id,
                        "timeout_sec": art.timeout_sec,
                        "resource_budget": dict(art.resource_budget) if art.resource_budget else None,
                        "effective_config_hash": art.effective_config_hash,
                        "prompt_hash": art.prompt_hash or art.tool_metadata.get("prompt_hash"),
                        "correlation_id": art.tool_metadata.get("correlation_id"),
                        "duration_seconds": art.duration_seconds,
                        "exit_code": target_exit_code,
                        "stdout_sha256": art.tool_metadata.get("stdout_sha256"),
                        "stderr_sha256": art.tool_metadata.get("stderr_sha256"),
                        "orchestration_status": getattr(art, "orchestration_status", art.status.value),
                        "generation_outcome": getattr(art, "generation_outcome", "NOT_RUN"),
                        "evm_outcome": getattr(art, "evm_outcome", "NOT_RUN"),
                        "security_verdict": art.security_verdict,
                        "replay_status": art.replay_status,
                        "persistence_status": art.persistence_status,
                        "replay_evidence": getattr(art, "replay_evidence", None) or art.tool_metadata.get("replay_evidence"),
                        "remote_evm_provenance": getattr(art, "remote_evm_provenance", None) or art.tool_metadata.get("remote_evm_provenance"),
                        "modal_invocation_provenance": getattr(art, "modal_invocation_provenance", None) or art.tool_metadata.get("modal_invocation_provenance"),
                    }
    
                env_manifest = self._get_environment_manifest()
                adapter_manifests[b_id] = AdapterRunManifest(
                    baseline_id=b_id,
                    baseline_name=adapter.baseline_name,
                    availability_status="AVAILABLE" if is_avail else "UNAVAILABLE",
                    availability_reason=avail_reason,
                    command=actual_adapter_cmd,
                    argv=actual_adapter_argv,
                    planned_command=planned_cmd,
                    planned_argv=planned_argv,
                    timeout_sec=actual_timeout_sec,
                    resource_budget=actual_resource_budget,
                    config_hash=actual_config_hash,
                    planned_timeout_sec=planned_timeout_sec,
                    planned_resource_budget=planned_resource_budget,
                    planned_config_hash=planned_config_hash,
                    duration_seconds=adapter_duration,
                    target_count=len(public_targets),
                    completed_targets=sum(1 for a in baseline_artifacts if a.status == ExecutionStatus.SUCCESS),
                    cost_status="unmeasured",
                    cost_usd=None,
                    remote_evm_environment=env_manifest.remote_evm_environment,
                    artifact_files=adapter_artifact_files,
                    per_target_provenance=per_target_provenance,
                )
    
        rel_artifacts_dir = None
        if save_results:
            try:
                rel_artifacts_dir = str(run_artifacts_dir.relative_to(base_dir)).replace("\\", "/")
            except ValueError:
                rel_artifacts_dir = str(run_artifacts_dir).replace("\\", "/")

        # Build full reproducibility manifest
        total_duration = round(time.time() - suite_start_time, 3)
        env_manifest = self._get_environment_manifest()
        repro_manifest = RunReproducibilityManifest(
            manifest_version="1.0.0",
            run_id=run_id,
            timestamp_utc=timestamp,
            execution_mode="SYNTHETIC_SMOKE_TEST" if mode == "smoke" else "REAL_EXPERIMENT",
            is_synthetic_smoke=(mode == "smoke"),
            git=self._get_git_manifest(),
            environment=env_manifest,
            dataset=self._get_dataset_manifest(public_targets),
            adapters=adapter_manifests,
            remote_evm_environment=env_manifest.remote_evm_environment,
            total_duration_seconds=total_duration,
        )

        # Enforce git reproducibility manifest integrity
        effective_require_clean = (
            require_clean
            if require_clean is not None
            else ((mode == "real") and save_results and not (os.environ.get("AEGIS_ALLOW_DIRTY") == "1"))
        )
        if commit_sha != "unknown":
            verify_manifest_git_integrity(
                repro_manifest, run_artifacts_dir, expected_commit_sha=commit_sha, require_clean=effective_require_clean
            )

        rel_manifest_file = None
        if save_results and rel_artifacts_dir:
            rel_manifest_file = f"{rel_artifacts_dir}/reproducibility_manifest.json"

        report: Dict[str, Any] = {
            "run_id": run_id,
            "benchmark_version": self.dataset.version,
            "execution_mode": "SYNTHETIC_SMOKE_TEST" if mode == "smoke" else "REAL_EXPERIMENT",
            "is_synthetic_smoke": (mode == "smoke"),
            "model_id": model_id,
            "provider": provider if mode == "real" else "synthetic_smoke",
            "baseline5_provider": b5_provider if mode == "real" else "synthetic_smoke",
            "baseline5_model_id": b5_model_id if mode == "real" else "synthetic_smoke",
            "git_commit_sha": commit_sha,
            "evaluated_at": timestamp,
            "total_targets_evaluated": len(public_targets),
            "vulnerable_targets": sum(1 for gt in ground_truth_map.values() if gt.is_vulnerable),
            "synthetic_controls": sum(1 for gt in ground_truth_map.values() if not gt.is_vulnerable),
            "artifacts_directory": rel_artifacts_dir,
            "reproducibility_manifest": rel_manifest_file,
            "reproducibility_manifest_summary": repro_manifest.to_dict(),
            "baselines": results,
        }

        if save_results:
            # 1. Main benchmark_results.json
            output_file = self.dataset_path.parent / "benchmark_results.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            # 2. Run summary inside the artifacts run directory
            summary_file = run_artifacts_dir / "summary.json"
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            # 3. Reproducibility manifest inside run directory
            manifest_file = run_artifacts_dir / "reproducibility_manifest.json"
            with open(manifest_file, "w", encoding="utf-8") as f:
                json.dump(repro_manifest.to_dict(), f, indent=2)

            # 4. Latest summary pointer
            latest_file = self.artifacts_base_dir / "latest_summary.json"
            with open(latest_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        return report


def main():
    parser = argparse.ArgumentParser(description="Aegis-RLVR Multi-Baseline Benchmark Evaluation")
    parser.add_argument("--mode", choices=["smoke", "real"], default="smoke",
                        help="Execution mode: smoke (fast simulation for CI) or real (live tools)")
    parser.add_argument("--model-id", type=str, default="gemini-1.5-pro",
                        help="Model ID under evaluation")
    parser.add_argument("--provider", type=str, default="gemini", choices=["gemini", "openai"],
                        help="LLM provider for auditor/exploit baselines (Baselines 2-4)")
    parser.add_argument("--baseline5-provider", type=str, default=None,
                        choices=["modal_h100", "modal_t4", "gemini", "openai"],
                        help="Dedicated inference backend for Baseline 5 (Full Aegis-RLVR). Choices: modal_h100, modal_t4, gemini, openai. Defaults to --provider if omitted.")
    parser.add_argument("--baseline5-model-id", type=str, default=None,
                        help="Model ID override for Baseline 5 inference backend (e.g. qtum/Qwen3-Coder-30B-A3B-Audit).")
    parser.add_argument("--baselines", nargs="*", default=None,
                        help="Filter specific baseline IDs to run (e.g. baseline_1 baseline_5)")
    parser.add_argument("--artifacts-dir", type=str, default=None,
                        help="Directory to save per-target execution artifacts")
    parser.add_argument("--no-save", action="store_true", help="Do not write benchmark_results.json")
    args = parser.parse_args()

    artifacts_path = Path(args.artifacts_dir) if args.artifacts_dir else None
    suite = AegisBenchmarkSuite(artifacts_dir=artifacts_path)

    print(f"[*] Running Aegis-RLVR Benchmark Suite [Mode: {args.mode.upper()}] for {args.model_id}...")
    report = suite.run_benchmark(
        mode=args.mode,
        model_id=args.model_id,
        provider=args.provider,
        save_results=not args.no_save,
        baselines_to_run=args.baselines,
        baseline5_provider=args.baseline5_provider,
        baseline5_model_id=args.baseline5_model_id,
    )

    print(f"\n[+] Benchmark Complete ({report['evaluated_at']}):")
    print(f"    Mode: {report['execution_mode']} | Synthetic Smoke: {report['is_synthetic_smoke']}")
    print(f"    Commit: {report['git_commit_sha']} | Evaluated: {report['total_targets_evaluated']} targets")
    if report.get("artifacts_directory"):
        print(f"    Artifacts: {report['artifacts_directory']}\n")

    for b_id, metrics in report["baselines"].items():
        status = metrics.get("status", "SUCCESS")
        print(f"[{b_id}] {metrics['baseline_name']}")
        if status in ("UNAVAILABLE", "INCOMPLETE", "FAILED"):
            print(f"  STATUS: {status}")
            print(f"  Reason: {metrics.get('status_reason', 'Tool or credentials missing')}")
            print(f"  Completed Targets: {metrics.get('completed_targets', 0)}/{metrics.get('total_targets', 0)}")
            print(f"  Metrics: [N/A - Cannot calculate empirical precision/recall on unexecuted run]\n")
        else:
            prec = metrics.get('precision')
            prec_str = f"{prec:.2%}" if prec is not None else "N/A"
            rec = metrics.get('recall')
            rec_str = f"{rec:.2%}" if rec is not None else "N/A"
            f1 = metrics.get('f1_score')
            f1_str = f"{f1:.4f}" if f1 is not None else "N/A"
            fpr = metrics.get('false_positive_rate')
            fpr_str = f"{fpr:.2%}" if fpr is not None else "N/A"
            fnr = metrics.get('false_negative_rate')
            fnr_str = f"{fnr:.2%}" if fnr is not None else "N/A"
            vfr = metrics.get('verified_finding_rate')
            vfr_str = f"{vfr:.2%}" if vfr is not None else "N/A"
            rrr = metrics.get('replay_reproducibility_rate')
            rrr_str = f"{rrr:.2%}" if rrr is not None else "N/A"

            print(f"  STATUS: SUCCESS")
            print(f"  Precision: {prec_str} | Recall: {rec_str} | F1: {f1_str}")
            print(f"  FPR: {fpr_str} | FNR: {fnr_str}")
            print(f"  Verified Finding Rate: {vfr_str} | Replay Rate: {rrr_str}")
            print(f"  Candidates/Verified: {metrics.get('candidates_per_verified_finding')} | Latency: {metrics.get('average_duration_seconds')}s\n")


if __name__ == "__main__":
    main()
