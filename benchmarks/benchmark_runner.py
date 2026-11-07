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
import json
import os
import subprocess
import time
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Any, Optional

from core.schemas import TargetProgram
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

    def run_benchmark(
        self,
        mode: str = "smoke",
        model_id: str = "gemini-1.5-pro",
        provider: str = "gemini",
        save_results: bool = True,
        baselines_to_run: Optional[List[str]] = None,
        custom_adapters: Optional[Dict[str, BaselineAdapter]] = None,
    ) -> Dict[str, Any]:
        """
        Executes the benchmark suite across baselines.

        Args:
            mode: "smoke" for fast synthetic CI verification; "real" for live tool execution.
            model_id: Model identifier for LLM-based baselines.
            provider: LLM provider name ("gemini" or "openai").
            save_results: Whether to persist benchmark_results.json and per-target JSON artifacts.
            baselines_to_run: Optional list of baseline_ids to filter (e.g. ["baseline_1", "baseline_5"]).
            custom_adapters: Optional dictionary of adapter overrides (useful for testing).
        """
        if mode not in ("smoke", "real"):
            raise ValueError("mode must be 'smoke' or 'real'")

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
                "baseline_5": SyntheticSmokeAdapter("baseline_5", "Full Aegis-RLVR (Hypothesis + Isolated Oracle + Replay)"),
            }
        else:  # mode == "real"
            adapters = {
                "baseline_1": SlitherBaselineAdapter(),
                "baseline_2": LLMAuditorBaselineAdapter(model_id=model_id, provider=provider),
                "baseline_3": LLMUnverifiedPoCBaselineAdapter(model_id=model_id, provider=provider),
                "baseline_4": LLMNaiveFoundryBaselineAdapter(model_id=model_id, provider=provider),
                "baseline_5": FullAegisRLVRBaselineAdapter(model_id=model_id, provider=provider),
            }

        if baselines_to_run:
            adapters = {k: v for k, v in adapters.items() if k in baselines_to_run}

        run_artifacts_dir = self.artifacts_base_dir / run_id
        if save_results:
            run_artifacts_dir.mkdir(parents=True, exist_ok=True)

        results: Dict[str, Dict[str, Any]] = {}
        base_dir = self.dataset_path.parent.parent

        for b_id, adapter in adapters.items():
            baseline_artifacts: List[TargetExecutionArtifact] = []

            # Create baseline artifact directory
            if save_results:
                b_dir = run_artifacts_dir / b_id
                b_dir.mkdir(parents=True, exist_ok=True)

            for target in public_targets:
                # Adapters receive ONLY public TargetSpecification (zero ground-truth leakage)
                artifact = adapter.execute_target(target, base_dir=base_dir)
                baseline_artifacts.append(artifact)

                # Save per-target JSON artifact
                if save_results:
                    art_file = run_artifacts_dir / b_id / f"{target.contract_id}.json"
                    with open(art_file, "w", encoding="utf-8") as f:
                        json.dump(artifact.to_dict(), f, indent=2)

            # Post-run evaluation consuming artifacts and private GroundTruth
            eval_result: BaselineEvaluationResult = evaluate_baseline_run(
                baseline_id=b_id,
                baseline_name=adapter.baseline_name,
                artifacts=baseline_artifacts,
                ground_truth_map=ground_truth_map,
            )
            results[b_id] = eval_result.to_dict()

        rel_artifacts_dir = None
        if save_results:
            try:
                rel_artifacts_dir = str(run_artifacts_dir.relative_to(base_dir)).replace("\\", "/")
            except ValueError:
                rel_artifacts_dir = str(run_artifacts_dir).replace("\\", "/")

        report: Dict[str, Any] = {
            "benchmark_version": self.dataset.version,
            "execution_mode": "SYNTHETIC_SMOKE_TEST" if mode == "smoke" else "REAL_EXPERIMENT",
            "is_synthetic_smoke": (mode == "smoke"),
            "model_id": model_id,
            "provider": provider if mode == "real" else "synthetic_smoke",
            "git_commit_sha": commit_sha,
            "evaluated_at": timestamp,
            "total_targets_evaluated": len(public_targets),
            "vulnerable_targets": sum(1 for gt in ground_truth_map.values() if gt.is_vulnerable),
            "synthetic_controls": sum(1 for gt in ground_truth_map.values() if not gt.is_vulnerable),
            "artifacts_directory": rel_artifacts_dir,
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

            # 3. Latest summary pointer
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
                        help="LLM provider for auditor/exploit baselines")
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
