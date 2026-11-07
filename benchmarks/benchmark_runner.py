"""Empirical benchmark orchestration: no executable adapters means NOT_RUN."""
from __future__ import annotations
import json, time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

BASELINES = {
    "baseline_1": "Static Analysis Only (Slither)",
    "baseline_2": "LLM Auditor Only",
    "baseline_3": "LLM Auditor + Exploit Generation (unverified PoC)",
    "baseline_4": "LLM + Naive Foundry",
    "baseline_5": "Full Aegis-RLVR",
}
Adapter = Callable[[Dict[str, Any]], Mapping[str, Any]]

@dataclass
class BaselineMetrics:
    baseline_id: str
    baseline_name: str
    status: str = "NOT_RUN"
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None
    false_negative_rate: Optional[float] = None
    exploit_success_rate: Optional[float] = None
    verified_finding_rate: Optional[float] = None
    replay_reproducibility_rate: Optional[float] = None
    candidates_per_verified_finding: Optional[float] = None
    average_duration_seconds: Optional[float] = None
    estimated_cost_usd_per_target: Optional[float] = None
    details: list[Dict[str, Any]] = field(default_factory=list)

    def calculate_derived_metrics(self, candidates, verified, replayed, duration, cost, count):
        predicted = self.true_positives + self.false_positives
        actual_p = self.true_positives + self.false_negatives
        actual_n = self.true_negatives + self.false_positives
        self.precision = self.true_positives / predicted if predicted else None
        self.recall = self.true_positives / actual_p if actual_p else None
        if self.precision is not None and self.recall is not None and self.precision + self.recall:
            self.f1_score = 2 * self.precision * self.recall / (self.precision + self.recall)
        self.false_positive_rate = self.false_positives / actual_n if actual_n else None
        self.false_negative_rate = self.false_negatives / actual_p if actual_p else None
        self.exploit_success_rate = verified / candidates if candidates else None
        self.verified_finding_rate = verified / actual_p if actual_p else None
        self.replay_reproducibility_rate = replayed / verified if verified else None
        self.candidates_per_verified_finding = candidates / verified if verified else None
        self.average_duration_seconds = duration / count if count else None
        self.estimated_cost_usd_per_target = cost / count if count else None

class AegisBenchmarkSuite:
    def __init__(self, dataset_path=None, adapters=None):
        self.dataset_path = Path(dataset_path or Path(__file__).parent / "benchmark_dataset.json")
        self.adapters = dict(adapters or {})
        with self.dataset_path.open("r", encoding="utf-8") as stream:
            self.dataset = json.load(stream)

    def get_all_targets(self):
        targets = []
        for cls in self.dataset.get("classes", []):
            targets.extend(cls.get("targets", []))
        targets.extend(self.dataset.get("synthetic_controls", []))
        return targets

    @staticmethod
    def _validate_observation(observation, target_id):
        if not isinstance(observation, Mapping):
            raise TypeError(f"Adapter result for {target_id} must be a mapping")
        detected = observation.get("detected")
        if not isinstance(detected, bool):
            raise ValueError(f"Adapter result for {target_id} must include boolean 'detected'")
        out = {"detected": detected}
        for key in ("candidates_generated", "verified_breaches", "replayed_breaches"):
            value = observation.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{key} for {target_id} must be a non-negative integer")
            out[key] = value
        if out["replayed_breaches"] > out["verified_breaches"]:
            raise ValueError(f"replayed_breaches cannot exceed verified_breaches for {target_id}")
        if out["verified_breaches"] > out["candidates_generated"]:
            raise ValueError(f"verified_breaches cannot exceed candidates_generated for {target_id}")
        if out["verified_breaches"] and not observation.get("verification_evidence"):
            raise ValueError(f"verified_breaches for {target_id} require verification_evidence")
        if out["replayed_breaches"] and not observation.get("replay_evidence"):
            raise ValueError(f"replayed_breaches for {target_id} require replay_evidence")
        for key in ("duration_seconds", "cost_usd"):
            value = observation.get(key, 0.0)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise ValueError(f"{key} for {target_id} must be non-negative")
            out[key] = float(value)
        out["verification_evidence"] = observation.get("verification_evidence")
        out["replay_evidence"] = observation.get("replay_evidence")
        return out

    def _evaluate_adapter(self, baseline_id, name, adapter, targets):
        m = BaselineMetrics(baseline_id=baseline_id, baseline_name=name, status="COMPLETED")
        candidates = verified = replayed = 0
        duration = cost = 0.0
        for target in targets:
            obs = self._validate_observation(adapter(target), target["contract_id"])
            actual, predicted = bool(target["is_vulnerable"]), obs["detected"]
            if actual and predicted: m.true_positives += 1
            elif not actual and predicted: m.false_positives += 1
            elif not actual: m.true_negatives += 1
            else: m.false_negatives += 1
            candidates += obs["candidates_generated"]
            verified += obs["verified_breaches"]
            replayed += obs["replayed_breaches"]
            duration += obs["duration_seconds"]
            cost += obs["cost_usd"]
            m.details.append({"target_id": target["contract_id"], "is_vulnerable": actual, **obs})
        m.calculate_derived_metrics(candidates, verified, replayed, duration, cost, len(targets))
        return asdict(m)

    def run_benchmark(self, persist=True):
        targets = self.get_all_targets()
        if not targets: raise ValueError("Benchmark dataset contains no targets")
        results, completed = {}, 0
        for key, name in BASELINES.items():
            adapter = self.adapters.get(key)
            if adapter is None:
                results[key] = {
                    "baseline_id": key, "baseline_name": name, "status": "NOT_IMPLEMENTED",
                    "metrics": None, "reason": "No executable adapter supplied; no empirical result exists."
                }
            else:
                results[key] = self._evaluate_adapter(key, name, adapter, targets)
                completed += 1
        report = {
            "benchmark_version": self.dataset.get("benchmark_version", "1.0.0"),
            "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "overall_status": "NOT_RUN" if completed == 0 else ("COMPLETED" if completed == len(BASELINES) else "PARTIAL"),
            "metrics_are_empirical": completed > 0,
            "total_targets": len(targets),
            "vulnerable_targets": sum(bool(t["is_vulnerable"]) for t in targets),
            "synthetic_controls": sum(not bool(t["is_vulnerable"]) for t in targets),
            "baselines": results,
        }
        if persist:
            with (self.dataset_path.parent / "benchmark_results.json").open("w", encoding="utf-8") as out:
                json.dump(report, out, indent=2, allow_nan=False)
                out.write("\n")
        return report

if __name__ == "__main__":
    report = AegisBenchmarkSuite().run_benchmark()
    print(f"Benchmark status: {report['overall_status']}")
    if report["overall_status"] == "NOT_RUN":
        print("No executable baseline adapters registered; no empirical metrics generated.")
    for key, baseline in report["baselines"].items():
        print(f"[{key}] {baseline['status']}")
