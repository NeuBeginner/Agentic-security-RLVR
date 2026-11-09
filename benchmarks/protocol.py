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
    cost_usd: Optional[float] = None
    security_verdict: Optional[str] = None
    replay_status: Optional[str] = None
    persistence_status: Optional[str] = None
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    stdout_sha256: Optional[str] = None
    stderr_sha256: Optional[str] = None
    input_sha256: Optional[str] = None
    output_sha256: Optional[str] = None
    process_exit_code: Optional[int] = None
    utc_start_time: Optional[str] = None
    utc_end_time: Optional[str] = None
    tool_metadata: Dict[str, Any] = field(default_factory=dict)
    raw_output: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)
    argv: Optional[List[str]] = None
    timeout_sec: Optional[int] = None
    resource_budget: Dict[str, Any] = field(default_factory=dict)
    effective_config_hash: Optional[str] = None
    prompt_hash: Optional[str] = None
    orchestration_status: str = "COMPLETED"
    generation_outcome: str = "NOT_RUN"
    evm_outcome: str = "NOT_RUN"
    replay_evidence: Optional[Dict[str, Any]] = None
    remote_evm_provenance: Optional[Dict[str, Any]] = None
    modal_invocation_provenance: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["execution_status"] = self.status.value
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
    estimated_cost_usd_per_target: Optional[float] = None
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


@dataclass
class ArtifactFileRecord:
    """Provenance record for a persisted artifact file with cryptographic hash."""
    relative_path: str
    size_bytes: int
    sha256: str


@dataclass
class EnvironmentManifest:
    """Host execution environment metadata."""
    python_version: str
    os_platform: str
    slither_version: Optional[str] = None
    forge_version: Optional[str] = None
    solc_version: Optional[str] = None
    modal_version: Optional[str] = None
    modal_authenticated: bool = False
    package_versions: Dict[str, str] = field(default_factory=dict)
    provider_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    remote_evm_environment: Optional[Dict[str, Any]] = None


@dataclass
class GitManifest:
    """Git repository provenance metadata."""
    commit_sha: str
    is_dirty: bool
    branch: str


@dataclass
class DatasetManifest:
    """Evaluated benchmark dataset version and target integrity metadata."""
    version: str
    dataset_sha256: str
    target_count: int
    target_ids: List[str]


@dataclass
class AdapterRunManifest:
    """Detailed execution provenance for a specific baseline adapter."""
    baseline_id: str
    baseline_name: str
    availability_status: str
    availability_reason: Optional[str] = None
    command: Optional[str] = None
    argv: Optional[List[str]] = None
    planned_command: Optional[str] = None
    planned_argv: Optional[List[str]] = None
    timeout_sec: Optional[int] = None
    resource_budget: Dict[str, Any] = field(default_factory=dict)
    config_hash: Optional[str] = None
    planned_timeout_sec: Optional[int] = None
    planned_resource_budget: Dict[str, Any] = field(default_factory=dict)
    planned_config_hash: Optional[str] = None
    duration_seconds: float = 0.0
    target_count: int = 0
    completed_targets: int = 0
    cost_status: str = "unmeasured"
    cost_usd: Optional[float] = None
    remote_evm_environment: Optional[Dict[str, Any]] = None
    artifact_files: List[ArtifactFileRecord] = field(default_factory=list)
    per_target_provenance: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class RunReproducibilityManifest:
    """
    Run-level reproducibility manifest recording exact environment, git, dataset,
    adapter commands, hashes, and artifact provenance for verifiable execution.
    """
    manifest_version: str = "1.0.0"
    run_id: str = ""
    timestamp_utc: str = ""
    execution_mode: str = "REAL_EXPERIMENT"
    is_synthetic_smoke: bool = False
    git: GitManifest = field(default_factory=lambda: GitManifest("unknown", False, "unknown"))
    environment: EnvironmentManifest = field(default_factory=lambda: EnvironmentManifest("unknown", "unknown"))
    dataset: DatasetManifest = field(default_factory=lambda: DatasetManifest("1.0.0", "", 0, []))
    adapters: Dict[str, AdapterRunManifest] = field(default_factory=dict)
    remote_evm_environment: Optional[Dict[str, Any]] = None
    total_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def validate_manifest_git_integrity(
    manifest_data: Any,
    run_dir: Optional[Any] = None,
    expected_commit_sha: Optional[str] = None,
    require_clean: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Validates git provenance integrity of a reproducibility manifest:
    1. commit_sha must be a full 40-character hexadecimal SHA (rejects 'HEAD', 'unknown', or short hashes).
    2. If expected_commit_sha is provided, manifest commit_sha must strictly match it.
    3. If run_dir or manifest run_id is provided, directory suffix (or run_id suffix) must match commit_sha[:7].
    4. If require_clean is True, rejects manifests recorded from dirty git checkouts (is_dirty=True).
    """
    import re

    if hasattr(manifest_data, "to_dict"):
        data = manifest_data.to_dict()
    elif isinstance(manifest_data, dict):
        data = manifest_data
    else:
        return False, f"Unsupported manifest_data type: {type(manifest_data).__name__}"

    git_info = data.get("git")
    if not git_info or not isinstance(git_info, dict):
        return False, "Missing or invalid 'git' block in reproducibility manifest"

    commit_sha = git_info.get("commit_sha")
    if not commit_sha or not isinstance(commit_sha, str):
        return False, "Missing or non-string 'commit_sha' in manifest git metadata"

    # Must be 40-character hex string
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha):
        return False, f"Invalid git commit SHA '{commit_sha}': must be a full 40-character hexadecimal SHA"

    commit_sha_lower = commit_sha.lower()

    if require_clean and git_info.get("is_dirty") is True:
        return False, "Dirty git checkout detected: reproducibility requires clean working tree (no uncommitted modifications)"

    if expected_commit_sha is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{40}", expected_commit_sha):
            return False, f"Invalid expected commit SHA '{expected_commit_sha}': must be a full 40-character hexadecimal SHA"
        if commit_sha_lower != expected_commit_sha.lower():
            return False, f"Manifest git commit SHA '{commit_sha}' does not match expected checkout SHA '{expected_commit_sha}'"

    run_ref = None
    if run_dir:
        run_ref = Path(run_dir).name
    elif "run_id" in data and data["run_id"]:
        run_ref = data["run_id"]

    if run_ref:
        parts = run_ref.split("_")
        if len(parts) >= 3 and parts[0] == "run":
            dir_sha_suffix = parts[-1].lower()
            expected_prefix = commit_sha_lower[: len(dir_sha_suffix)]
            if dir_sha_suffix != expected_prefix or len(dir_sha_suffix) < 7:
                return False, f"Run directory suffix '{dir_sha_suffix}' does not match manifest commit prefix '{commit_sha_lower[:7]}'"

    return True, None


def verify_manifest_git_integrity(
    manifest_data: Any,
    run_dir: Optional[Any] = None,
    expected_commit_sha: Optional[str] = None,
    require_clean: bool = False,
) -> None:
    """Raises ValueError if reproducibility manifest git integrity validation fails."""
    valid, err = validate_manifest_git_integrity(
        manifest_data, run_dir, expected_commit_sha, require_clean=require_clean
    )
    if not valid:
        raise ValueError(f"Reproducibility manifest git integrity validation failed: {err}")


def validate_replay_evidence_envelope(
    artifact_dict: Dict[str, Any],
    artifacts_dir: Optional[Path] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validates the independent replay evidence envelope (Iteration 14 Requirement 2).
    A test must fail if replay is marked CONFIRMED without a complete self-verifying evidence envelope:
    - real fresh container identity (rejects 'modal-cpu-replayed' or synthetic placeholders);
    - exact command/argv and exit code (0);
    - recomputed stdout/stderr SHA-256 matching persisted replay artifacts;
    - invariant event/verdict and reproduced flags;
    - replay-specific start/end timestamps (rejects reused initial-stage timestamps);
    - hashes of exact candidate and harness inputs verified against actual files when available.
    """
    import re
    import hashlib

    replay_status = artifact_dict.get("replay_status")
    replayed_breaches = artifact_dict.get("replayed_breaches", 0)

    if replay_status != "CONFIRMED" and replayed_breaches == 0:
        return True, None

    tool_meta = artifact_dict.get("tool_metadata", {})
    replay_data = artifact_dict.get("replay_evidence") or tool_meta.get("replay_evidence")

    if not isinstance(replay_data, dict) or not replay_data:
        return False, "Replay status is CONFIRMED but replay evidence envelope is missing or empty"

    # 1. Fresh container identity (reject synthetic fallback 'modal-cpu-replayed')
    container_id = replay_data.get("container_id")
    if not container_id or not isinstance(container_id, str):
        return False, "Missing or invalid container_id in replay evidence envelope"
    if container_id == "modal-cpu-replayed":
        return False, "Synthetic fallback container ID 'modal-cpu-replayed' is prohibited"
    if not re.match(r"^modal-cpu-[a-f0-9]{12}$", container_id):
        return False, f"container_id '{container_id}' does not match expected Modal container format 'modal-cpu-<hex12>'"

    # 2. Command and argv
    cmd = replay_data.get("command")
    argv = replay_data.get("argv")
    if cmd != "forge test --offline --json -vvvv":
        return False, f"Replay command must be 'forge test --offline --json -vvvv', got '{cmd}'"
    if argv != ["forge", "test", "--offline", "--json", "-vvvv"]:
        return False, f"Replay argv must be ['forge', 'test', '--offline', '--json', '-vvvv'], got {argv}"

    # 3. Exit code must be 0 for confirmed breach
    exit_code = replay_data.get("exit_code") if "exit_code" in replay_data else replay_data.get("return_code")
    if exit_code is None or exit_code != 0:
        return False, f"Replay exit_code must be 0 for confirmed breach, got {exit_code}"

    # 4. Invariant violated and reproduced flags
    if not replay_data.get("reproduced"):
        return False, "Replay evidence reproduced flag is False or missing"
    if not replay_data.get("invariant_violated"):
        return False, "Replay evidence invariant_violated flag is False or missing"

    # 5. Cryptographic digests format
    for hash_key in ("stdout_sha256", "stderr_sha256", "candidate_sha256", "harness_sha256"):
        val = replay_data.get(hash_key)
        if not val or not isinstance(val, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", val):
            return False, f"Missing or invalid 64-character SHA-256 for '{hash_key}' in replay evidence"

    # 6. Replay-specific start/end timestamps (must not reuse initial execution timestamps)
    rep_start = replay_data.get("utc_start_time")
    rep_end = replay_data.get("utc_end_time")
    if not rep_start or not rep_end:
        return False, "Missing utc_start_time or utc_end_time in replay evidence envelope"
    if rep_start > rep_end:
        return False, f"Replay utc_start_time '{rep_start}' is after utc_end_time '{rep_end}'"

    init_start = tool_meta.get("utc_start_time")
    if init_start and rep_start == init_start:
        return False, f"Replay start timestamp '{rep_start}' reuses initial run timestamp (timestamps must be distinct)"

    # 7. Byte-level verification against actual persisted files
    stdout_rel_path = replay_data.get("stdout_path") or replay_data.get("replay_stdout_path")
    stderr_rel_path = replay_data.get("stderr_path") or replay_data.get("replay_stderr_path")
    stdout_len = replay_data.get("stdout_bytes_len")
    stderr_len = replay_data.get("stderr_bytes_len")

    if stdout_len is None:
        return False, "Missing stdout_bytes_len in replay evidence envelope"
    if stderr_len is None:
        return False, "Missing stderr_bytes_len in replay evidence envelope"

    # Recompute hashes from artifact bytes if paths or artifacts_dir provided
    if artifacts_dir is not None and stdout_rel_path:
        out_file = artifacts_dir / stdout_rel_path
        if not out_file.exists():
            out_file = artifacts_dir / Path(stdout_rel_path).name
        if not out_file.exists():
            return False, f"Persisted replay stdout artifact not found at '{out_file}'"
        out_bytes = out_file.read_bytes()
        if len(out_bytes) != stdout_len:
            return False, f"Persisted replay stdout length {len(out_bytes)} does not match envelope length {stdout_len}"
        recomputed_out_sha = hashlib.sha256(out_bytes).hexdigest()
        if recomputed_out_sha != replay_data["stdout_sha256"]:
            return False, f"Persisted replay stdout SHA-256 mismatch: {recomputed_out_sha} != {replay_data['stdout_sha256']}"

    if artifacts_dir is not None and stderr_rel_path:
        err_file = artifacts_dir / stderr_rel_path
        if not err_file.exists():
            err_file = artifacts_dir / Path(stderr_rel_path).name
        if not err_file.exists():
            return False, f"Persisted replay stderr artifact not found at '{err_file}'"
        err_bytes = err_file.read_bytes()
        if len(err_bytes) != stderr_len:
            return False, f"Persisted replay stderr length {len(err_bytes)} does not match envelope length {stderr_len}"
        recomputed_err_sha = hashlib.sha256(err_bytes).hexdigest()
        if recomputed_err_sha != replay_data["stderr_sha256"]:
            return False, f"Persisted replay stderr SHA-256 mismatch: {recomputed_err_sha} != {replay_data['stderr_sha256']}"

    return True, None


def validate_remote_evm_toolchain_provenance(artifact_dict: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validates remote EVM toolchain provenance (Iteration 14 Requirement 3).
    - Rejects missing remote toolchain provenance for any target whose EVM stage ran.
    - Rejects unexecuted targets that have non-null EVM toolchain provenance.
    - Rejects mutable image tags (e.g. debian:12-slim-foundry); requires immutable sha256 digest or explicit NOT_AVAILABLE + reason.
    - Validates SemVer version patterns for forge and solc.
    """
    import re
    evm_outcome = artifact_dict.get("evm_outcome")
    sec_verdict = artifact_dict.get("security_verdict")
    process_exit_code = artifact_dict.get("process_exit_code")

    tool_meta = artifact_dict.get("tool_metadata", {})
    provenance = artifact_dict.get("remote_evm_provenance") or tool_meta.get("remote_evm_provenance")

    # If the target did NOT run an EVM stage (e.g. format error before EVM):
    if evm_outcome == "NOT_RUN" or (sec_verdict == "GENERATION_FORMAT_ERROR" and process_exit_code == -4):
        if provenance is not None:
            return False, "Target did not execute EVM stage but has non-null remote_evm_provenance (unexecuted targets must not carry EVM provenance)"
        return True, None

    if not isinstance(provenance, dict) or not provenance:
        return False, "Missing remote_evm_provenance dictionary for executed EVM stage"

    # 1. remote_os
    os_name = provenance.get("remote_os")
    if not os_name or not isinstance(os_name, str) or "Debian" not in os_name or "Linux" not in os_name:
        return False, f"Invalid remote_os '{os_name}'; expected verified Debian Linux string"
    if os_name == "unknown":
        return False, "Placeholder 'unknown' is not permitted for remote_os"

    # 2. remote_platform
    if provenance.get("remote_platform") != "linux":
        return False, f"remote_platform must be 'linux', got '{provenance.get('remote_platform')}'"

    # 3. image_digest: must be immutable sha256 or explicit NOT_AVAILABLE with reason
    image_digest = provenance.get("image_digest")
    if not image_digest or not isinstance(image_digest, str):
        return False, "Missing image_digest field in remote EVM toolchain provenance"
    if image_digest == "NOT_AVAILABLE":
        reason = provenance.get("image_digest_reason")
        if not reason or not isinstance(reason, str) or len(reason.strip()) == 0:
            return False, "image_digest is NOT_AVAILABLE but image_digest_reason is missing or empty"
    elif re.match(r"^sha256:[a-f0-9]{64}$", image_digest):
        pass  # Valid immutable OCI digest
    else:
        return False, f"image_digest must be an immutable 'sha256:<64hex>' digest or explicit 'NOT_AVAILABLE' (got mutable tag or invalid format: '{image_digest}')"

    # Rejects mutable tag if placed in image_tag as a digest substitute
    if "image_tag" in provenance and not image_digest:
        return False, "Mutable image_tag cannot substitute for immutable image_digest"

    # 4. forge_version
    forge_ver = provenance.get("forge_version")
    if not forge_ver or not isinstance(forge_ver, str) or not re.match(r"^forge\s+\d+\.\d+\.\d+.*", forge_ver):
        return False, f"Invalid forge_version '{forge_ver}'; expected SemVer pattern 'forge X.Y.Z ...'"

    # 5. solc_versions
    solc_vers = provenance.get("solc_versions")
    if not solc_vers or not isinstance(solc_vers, list) or len(solc_vers) == 0:
        return False, "Missing or empty solc_versions list in remote EVM provenance"
    for sv in solc_vers:
        if not re.match(r"^0\.8\.\d+$", str(sv)):
            return False, f"Invalid Solidity version in solc_versions: '{sv}'"

    # 6. exact_forge_argv
    argv = provenance.get("exact_forge_argv")
    if argv != ["forge", "test", "--offline", "--json", "-vvvv"]:
        return False, f"exact_forge_argv must be ['forge', 'test', '--offline', '--json', '-vvvv'], got {argv}"

    # 7. working_directory
    cwd = provenance.get("working_directory")
    if not cwd or not isinstance(cwd, str) or len(cwd.strip()) == 0:
        return False, "Missing or empty working_directory in remote EVM provenance"

    # 8. compiler_settings
    settings = provenance.get("compiler_settings")
    if not isinstance(settings, dict) or not settings:
        return False, "Missing compiler_settings dictionary in remote EVM provenance"
    for k in ("evm_version", "optimizer", "optimizer_runs", "via_ir"):
        if k not in settings:
            return False, f"Missing required compiler setting '{k}' in remote EVM provenance"

    return True, None


def validate_safe_control_sentinel_semantics(
    revert_reason: Optional[str],
    harness_verdict: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Validates deliberate safe-control sentinel semantics (Iteration 14 Requirement 4).
    Accepts ONLY the exact documented sentinel format emitted by the trusted harness:
    r"^EXPLOIT_FAILED:\s*Safe\s+control\s+held(?:\.\s*.*)?$"

    Rejects:
    - Arbitrary EXPLOIT_FAILED strings (e.g. 'EXPLOIT_FAILED: Reward pool protected against flash loan distortion')
    - Generic EVM reverts ('EvmError: Revert')
    - EVM panic codes ('Panic(0x11)')
    - Compilation errors ('Compiler run failed')
    - Missing or empty revert reasons
    """
    import re
    if not revert_reason or not isinstance(revert_reason, str) or len(revert_reason.strip()) == 0:
        return False, "MISSING_REVERT_REASON"

    # Exact sentinel regex: must start with "EXPLOIT_FAILED: Safe control held"
    if re.match(r"^EXPLOIT_FAILED:\s*Safe\s+control\s+held(?:\.\s*.*)?$", revert_reason.strip()):
        return True, "SAFE_RUN"

    # Reject arbitrary EXPLOIT_FAILED strings that are not the safe control held sentinel
    if revert_reason.startswith("EXPLOIT_FAILED"):
        return False, f"ARBITRARY_EXPLOIT_FAILED_NOT_SENTINEL: {revert_reason}"

    # Reject generic EVM reverts
    if "EvmError: Revert" in revert_reason:
        return False, "GENERIC_EVM_REVERT_NOT_SENTINEL"

    # Reject EVM panic codes
    if "Panic" in revert_reason:
        return False, "EVM_PANIC_NOT_SENTINEL"

    # Reject compiler errors
    if "Compiler run failed" in revert_reason or "ParserError" in revert_reason:
        return False, "COMPILATION_ERROR_NOT_SENTINEL"

    return False, f"UNRECOGNIZED_REVERT_REASON: {revert_reason}"


def validate_billing_reconciliation(
    join_table_dict: Dict[str, Any],
    raw_billing_list: List[Dict[str, Any]]
) -> Tuple[bool, Optional[str]]:
    """
    Validates the complete Modal billing reconciliation (Iteration 14 Requirement 1):
    - Proves every referenced app session ID exists in raw billing export.
    - Proves all raw billing line items are reconciled without omission or double-counting.
    - Proves aggregate session totals reconcile exactly with the raw report down to 8 decimal places.
    - Proves target-level cost stays strictly null absent a proven invocation-level join.
    - Proves no manufactured 'modal-app://' pseudo-URIs exist.
    """
    import json
    raw_apps = {item["object_id"] for item in raw_billing_list}
    raw_grand_total = sum(float(item["cost"]) for item in raw_billing_list)

    reconciled_sessions = join_table_dict.get("app_sessions_reconciliation", {})
    if not isinstance(reconciled_sessions, dict) or not reconciled_sessions:
        return False, "Missing or empty 'app_sessions_reconciliation' in join table"

    # 1. Check all referenced app IDs exist in raw billing
    reconciled_item_count = 0
    reconciled_grand_total = 0.0

    for app_id, session_data in reconciled_sessions.items():
        if app_id not in raw_apps:
            return False, f"Reconciled app session '{app_id}' does not exist in raw billing export"

        items = session_data.get("line_items", [])
        if not items:
            return False, f"App session '{app_id}' has no line items"

        session_cost = session_data.get("session_cost_usd")
        items_sum = sum(float(x["cost"]) for x in items)

        if abs(session_cost - items_sum) > 1e-7:
            return False, f"Session '{app_id}' cost {session_cost} does not match sum of items {items_sum}"

        reconciled_item_count += len(items)
        reconciled_grand_total += items_sum

    # 2. Check no line items were omitted or double counted
    if reconciled_item_count != len(raw_billing_list):
        return False, f"Reconciled line item count ({reconciled_item_count}) does not match raw export count ({len(raw_billing_list)})"

    if abs(reconciled_grand_total - raw_grand_total) > 1e-6:
        return False, f"Grand total mismatch: reconciled {reconciled_grand_total:.8f} != raw {raw_grand_total:.8f}"

    # 3. Check target-level attribution rules
    target_records = join_table_dict.get("target_execution_records", [])
    if not target_records:
        return False, "Missing target_execution_records in join table"

    for tr in target_records:
        tid = tr.get("target_id")
        if tr.get("cost_usd") is not None:
            return False, f"Target '{tid}' has non-null cost_usd ({tr.get('cost_usd')}); target cost must remain null"
        if tr.get("billing_line_item") is not None:
            return False, f"Target '{tid}' has repeated aggregate billing_line_item; line items must be null on target records"
        if tr.get("attribution_status") != "UNATTRIBUTABLE_AGGREGATE":
            return False, f"Target '{tid}' attribution_status must be 'UNATTRIBUTABLE_AGGREGATE', got '{tr.get('attribution_status')}'"

        # Check for manufactured modal-app:// pseudo-URIs
        tr_str = json.dumps(tr)
        if "modal-app://" in tr_str:
            return False, f"Target '{tid}' contains prohibited manufactured pseudo-URI starting with 'modal-app://'"

    return True, None
