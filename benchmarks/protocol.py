"""
benchmarks/protocol.py

Unified Benchmark Protocol for Aegis-RLVR:
1. Strict boundary separation between public TargetSpecification and private GroundTruth.
2. Machine-readable execution artifacts with full provenance (tool versions, prompt hashes, stdout/stderr).
3. Explicit execution status handling (SUCCESS, UNAVAILABLE, FAILED, INCOMPLETE).
4. No synthetic metric fabrication: unavailable tools yield INCOMPLETE results, never false 0% or 100%.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


class ExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True)
class TargetSpecification:
    """
    Public target program specification provided to baseline auditors and exploit generators.
    Ground-truth vulnerability status is strictly excluded to prevent information leakage.
    """
    contract_id: str
    target_name: str
    source_file: str
    harness_file: str
    difficulty: str = "medium"
    description: str = ""

    def load_source_code(self, base_dir: Optional[Path] = None) -> str:
        path = Path(self.source_file)
        if not path.is_absolute() and base_dir:
            path = base_dir / path
        if not path.exists():
            raise FileNotFoundError(f"Source file {path} not found for target {self.contract_id}")
        return path.read_text(encoding="utf-8")


@dataclass(frozen=True)
class GroundTruth:
    """
    Private ground truth maintained separately from baseline execution.
    Only the post-execution evaluator has access to GroundTruth for computing confusion matrices.
    """
    contract_id: str
    is_vulnerable: bool
    vulnerable_functions: List[str] = field(default_factory=list)
    ground_truth_invariant: str = "NONE"


@dataclass
class TargetExecutionArtifact:
    """
    Detailed, auditable execution record for a single target within a baseline.
    Retains all provenance information, tool exit codes, and raw outputs.
    """
    baseline_id: str
    target_id: str
    target_name: str
    status: ExecutionStatus
    unavailable_reason: Optional[str] = None
    detected: bool = False
    candidates_generated: int = 0
    verified_breaches: int = 0
    replayed_breaches: int = 0
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    tool_metadata: Dict[str, Any] = field(default_factory=dict)
    raw_output: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class BaselineEvaluationResult:
    """
    Evaluated benchmark metrics for a single baseline across all targets.
    If the baseline was UNAVAILABLE, precision/recall/F1 are None, preventing fake 0/1 metrics.
    """
    baseline_id: str
    baseline_name: str
    status: ExecutionStatus
    status_reason: Optional[str] = None
    total_targets: int = 0
    completed_targets: int = 0
    true_positives: Optional[int] = None
    false_positives: Optional[int] = None
    true_negatives: Optional[int] = None
    false_negatives: Optional[int] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None
    false_negative_rate: Optional[float] = None
    exploit_success_rate: Optional[float] = None
    verified_finding_rate: Optional[float] = None
    replay_reproducibility_rate: Optional[float] = None
    candidates_per_verified_finding: Optional[float] = None
    average_duration_seconds: float = 0.0
    estimated_cost_usd_per_target: float = 0.0
    target_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    details: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class BenchmarkDataset:
    """
    Loads benchmark dataset and enforces strict separation between public targets and ground truth.
    """
    def __init__(self, dataset_path: Optional[Path] = None):
        if dataset_path is None:
            dataset_path = Path(__file__).parent / "benchmark_dataset.json"
        self.dataset_path = Path(dataset_path).resolve()
        self.raw_data = self._load_json(self.dataset_path)
        self.targets, self.ground_truth = self._parse_dataset()

    @staticmethod
    def _load_json(path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Benchmark dataset not found at {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _parse_dataset(self) -> Tuple[List[TargetSpecification], Dict[str, GroundTruth]]:
        targets: List[TargetSpecification] = []
        ground_truth: Dict[str, GroundTruth] = {}

        # 1. Parse vulnerable classes
        for c in self.raw_data.get("classes", []):
            for t in c.get("targets", []):
                spec = TargetSpecification(
                    contract_id=t["contract_id"],
                    target_name=t["target_name"],
                    source_file=t["source_file"],
                    harness_file=t.get("harness_file", ""),
                    difficulty=t.get("difficulty", "medium"),
                    description=t.get("description", ""),
                )
                targets.append(spec)
                ground_truth[spec.contract_id] = GroundTruth(
                    contract_id=spec.contract_id,
                    is_vulnerable=bool(t.get("is_vulnerable", True)),
                    vulnerable_functions=list(t.get("vulnerable_functions", [])),
                    ground_truth_invariant=str(t.get("ground_truth_invariant", "NONE")),
                )

        # 2. Parse synthetic safe controls
        for ctrl in self.raw_data.get("synthetic_controls", []):
            spec = TargetSpecification(
                contract_id=ctrl["contract_id"],
                target_name=ctrl["target_name"],
                source_file=ctrl["source_file"],
                harness_file=ctrl.get("harness_file", ""),
                difficulty="control",
                description=ctrl.get("description", "Safe control contract"),
            )
            targets.append(spec)
            ground_truth[spec.contract_id] = GroundTruth(
                contract_id=spec.contract_id,
                is_vulnerable=False,
                vulnerable_functions=[],
                ground_truth_invariant="NONE",
            )

        return targets, ground_truth

    @property
    def version(self) -> str:
        return self.raw_data.get("benchmark_version", "1.0.0")

    def get_public_targets(self) -> List[TargetSpecification]:
        """Returns the list of public target specifications without ground truth."""
        return list(self.targets)

    def get_ground_truth(self) -> Dict[str, GroundTruth]:
        """Returns the private mapping of contract_id -> GroundTruth for evaluator use only."""
        return dict(self.ground_truth)
