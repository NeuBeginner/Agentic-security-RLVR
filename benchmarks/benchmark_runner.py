"""
benchmarks/benchmark_runner.py

Aegis-RLVR Multi-Baseline Benchmark Runner.
Evaluates vulnerability detection and exploit verification accuracy across 5 distinct paradigms:
1. Baseline 1: Static Analysis Only (Slither AST / taint analysis)
2. Baseline 2: LLM Auditor Only (Zero-shot text vulnerability audit findings)
3. Baseline 3: LLM Auditor + LLM Exploit Generation (Unverified PoC synthesis)
4. Baseline 4: LLM Auditor + Exploit Generation + Naive Foundry (Text marker / Exit code 0)
5. Baseline 5: Full Aegis-RLVR (Hypothesis Pipeline + Isolated Runner + Trusted State Oracle + Independent Replay)

Calculates:
- Precision, Recall, F1 Score
- False-Positive Rate (FPR) and False-Negative Rate (FNR)
- Exploit Success Rate, Verified Finding Rate, Replay Reproducibility Rate
- Latency and estimated cost per target
- Real experimental results distinguished from synthetic smoke tests.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

import argparse
import json
import os
import subprocess
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Any, Optional

from core.schemas import (
    TargetProgram,
    ExploitPayload,
    AttackHypothesis,
    ResultCategory,
)
from sandbox.runner import (
    run_slither_analysis,
    run_payload_in_sandbox,
    verify_independent_replay_structured,
)
from core.hypothesis_manager import HypothesisManager
from core.evm_oracle import trusted_oracle


@dataclass
class BaselineMetrics:
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
    def __init__(self, dataset_path: Optional[Path] = None):
        if dataset_path is None:
            dataset_path = Path(__file__).parent / "benchmark_dataset.json"
        self.dataset_path = Path(dataset_path)
        self.dataset = self._load_dataset()

    def _load_dataset(self) -> Dict[str, Any]:
        with open(self.dataset_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_all_targets(self) -> List[Dict[str, Any]]:
        targets = []
        for c in self.dataset.get("classes", []):
            targets.extend(c.get("targets", []))
        for ctrl in self.dataset.get("synthetic_controls", []):
            targets.append(ctrl)
        return targets

    def _load_target_program(self, target_dict: Dict[str, Any]) -> TargetProgram:
        """Loads source code and trusted harness into TargetProgram schema."""
        src_path = Path(target_dict["source_file"])
        source_code = ""
        if src_path.exists():
            with open(src_path, "r", encoding="utf-8") as f:
                source_code = f.read()

        harness_code = None
        if "harness_file" in target_dict:
            h_path = Path(target_dict["harness_file"])
            if h_path.exists():
                with open(h_path, "r", encoding="utf-8") as f:
                    harness_code = f.read()

        invariants = []
        if target_dict.get("ground_truth_invariant") and target_dict["ground_truth_invariant"] != "NONE":
            invariants.append(target_dict["ground_truth_invariant"])

        return TargetProgram(
            name=target_dict["target_name"],
            source_code=source_code,
            trusted_harness_code=harness_code,
            invariants=invariants
        )

    def run_benchmark(
        self,
        mode: str = "smoke",
        model_id: str = "gemini-1.5-pro",
        save_results: bool = True
    ) -> Dict[str, Any]:
        """
        Executes benchmark comparison across 5 baseline architectures against all targets.
        
        Args:
            mode: "smoke" for deterministic fast verification without external API/GPU calls;
                  "real" for live experimental pipeline execution (Slither, Foundry, Oracle, Replay).
            model_id: Identifier of model evaluated.
            save_results: Whether to persist benchmark_results.json.
        """
        targets = self.get_all_targets()
        if mode == "real":
            raise NotImplementedError(
                "Real benchmark mode is disabled: executable adapters for every baseline are not implemented. "
                "Use --mode smoke only for synthetic CI plumbing; do not report smoke metrics as experimental results."
            )
        if mode != "smoke":
            raise ValueError("mode must be 'smoke' or 'real'")
        baseline_configs = [
            ("baseline_1", "Static Analysis Only (Slither)"),
            ("baseline_2", "LLM Auditor Only (Raw Text Findings)"),
            ("baseline_3", "LLM Auditor + Exploit Gen (Unverified PoC)"),
            ("baseline_4", "LLM + Naive Foundry (Exit Code 0 / Text Marker)"),
            ("baseline_5", "Full Aegis-RLVR (Hypothesis + Isolated Oracle + Replay)"),
        ]

        # Current commit SHA for provenance
        commit_sha = "unknown"
        try:
            commit_sha = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip()
        except Exception:
            pass

        results = {}
        for b_id, b_name in baseline_configs:
            metrics = self._evaluate_baseline(b_id, b_name, targets, mode=mode, model_id=model_id)
            results[b_id] = asdict(metrics)

        report = {
            "benchmark_version": self.dataset.get("benchmark_version", "1.0.0"),
            "execution_mode": "SYNTHETIC_SMOKE_TEST" if mode == "smoke" else "REAL_EXPERIMENT",
            "is_synthetic_smoke": (mode == "smoke"),
            "model_id": model_id,
            "git_commit_sha": commit_sha,
            "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
            "total_targets_evaluated": len(targets),
            "vulnerable_targets": sum(1 for t in targets if t["is_vulnerable"]),
            "synthetic_controls": sum(1 for t in targets if not t["is_vulnerable"]),
            "baselines": results
        }

        if save_results:
            output_file = self.dataset_path.parent / "benchmark_results.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        return report

    def _evaluate_baseline(
        self,
        b_id: str,
        b_name: str,
        targets: List[Dict[str, Any]],
        mode: str = "smoke",
        model_id: str = "gemini-1.5-pro"
    ) -> BaselineMetrics:
        metrics = BaselineMetrics(baseline_id=b_id, baseline_name=b_name)
        total_candidates = 0
        total_verified = 0
        total_replayed = 0
        total_duration = 0.0

        for target_info in targets:
            is_vuln = target_info["is_vulnerable"]
            target_id = target_info["contract_id"]
            target_prog = self._load_target_program(target_info)

            start_t = time.time()
            detected = False
            candidates = 0
            verified = 0
            replayed = 0
            cost = 0.0

            if mode != "smoke":
                raise NotImplementedError("Only explicitly synthetic smoke mode is implemented.")
            # Mode: "smoke" (synthetic deterministic fixtures for CI plumbing)
                if b_id == "baseline_1":
                    # Slither: high recall on structural issues, false positives on safe patterns
                    detected = target_id in ["REENT-01", "AC-01", "DOS-01", "SAFE-01", "SAFE-02"]
                    candidates = 0
                    verified = 0
                    replayed = 0
                    cost = 0.0
                elif b_id == "baseline_2":
                    # Raw LLM auditor: hallucinates on controls, 0 verified PoC
                    detected = target_id in [
                        "REENT-01", "ERC4626-01", "AC-01", "ORACLE-01", "FLASH-01",
                        "STATE-01", "SAFE-01", "SAFE-03"
                    ]
                    candidates = 0
                    verified = 0
                    replayed = 0
                    cost = 0.04
                elif b_id == "baseline_3":
                    # Unverified PoC synthesis: zero invariant verification
                    detected = target_id in ["REENT-01", "AC-01", "DOS-01", "SAFE-01"]
                    candidates = 4 if detected else 0
                    verified = 0
                    replayed = 0
                    cost = 0.10
                elif b_id == "baseline_4":
                    # Naive Foundry: fooled by exit 0 / log marker on safe controls
                    detected = target_id in [
                        "REENT-01", "AC-01", "DOS-01", "SIG-01", "PREC-01", "SAFE-01"
                    ]
                    candidates = 8 if detected else 0
                    verified = 5 if detected else 0
                    replayed = 3 if detected else 0
                    cost = 0.18
                elif b_id == "baseline_5":
                    # Full Aegis-RLVR: 0% False Positive Rate on safe controls, high verification
                    detected = is_vuln and target_id not in ["BRIDGE-01"]
                    candidates = 6 if detected else 2
                    verified = 1 if detected else 0
                    replayed = 1 if (detected and verified == 1) else 0
                    cost = 0.18

            elapsed = time.time() - start_t
            if mode == "smoke":
                elapsed = 0.1  # fast mock time

            total_candidates += candidates
            total_verified += verified
            total_replayed += replayed
            total_duration += elapsed

            # Confusion matrix accumulation
            if is_vuln and detected:
                metrics.true_positives += 1
            elif not is_vuln and detected:
                metrics.false_positives += 1
            elif not is_vuln and not detected:
                metrics.true_negatives += 1
            elif is_vuln and not detected:
                metrics.false_negatives += 1

            metrics.details.append({
                "target_id": target_id,
                "is_vulnerable": is_vuln,
                "detected": detected,
                "candidates_generated": candidates,
                "verified_breaches": verified,
                "replayed_breaches": replayed,
                "duration_seconds": round(elapsed, 3),
                "cost_usd": cost
            })

        metrics.average_duration_seconds = round(total_duration / max(1, len(targets)), 3)
        metrics.estimated_cost_usd_per_target = round(cost, 3)
        metrics.calculate_derived_metrics(total_candidates, total_verified, total_replayed)

        return metrics


def main():
    parser = argparse.ArgumentParser(description="Aegis-RLVR Multi-Baseline Benchmark Evaluation")
    parser.add_argument("--mode", choices=["smoke", "real"], default="smoke",
                        help="Execution mode: smoke (fast simulation for CI) or real (live tools)")
    parser.add_argument("--model-id", type=str, default="gemini-1.5-pro",
                        help="Model ID under evaluation")
    parser.add_argument("--no-save", action="store_true", help="Do not write benchmark_results.json")
    args = parser.parse_args()

    suite = AegisBenchmarkSuite()
    print(f"[*] Running Aegis-RLVR Benchmark Suite [Mode: {args.mode.upper()}] for {args.model_id}...")
    report = suite.run_benchmark(mode=args.mode, model_id=args.model_id, save_results=not args.no_save)

    print(f"\n[+] Benchmark Complete ({report['evaluated_at']}):")
    print(f"    Mode: {report['execution_mode']} | Synthetic Smoke: {report['is_synthetic_smoke']}")
    print(f"    Commit: {report['git_commit_sha']} | Evaluated: {report['total_targets_evaluated']} targets\n")

    for b_id, metrics in report["baselines"].items():
        print(f"[{b_id}] {metrics['baseline_name']}")
        print(f"  Precision: {metrics['precision']:.2%} | Recall: {metrics['recall']:.2%} | F1: {metrics['f1_score']:.4f}")
        print(f"  FPR: {metrics['false_positive_rate']:.2%} | FNR: {metrics['false_negative_rate']:.2%}")
        print(f"  Verified Finding Rate: {metrics['verified_finding_rate']:.2%} | Replay Rate: {metrics['replay_reproducibility_rate']:.2%}")
        print(f"  Candidates/Verified: {metrics['candidates_per_verified_finding']} | Latency: {metrics['average_duration_seconds']}s\n")


if __name__ == "__main__":
    main()
