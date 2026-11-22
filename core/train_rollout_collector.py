"""
core/train_rollout_collector.py

Isolated GRPO training rollout collector (Blocker 1, Part 2).

Responsibilities:
1. Fail-closed data isolation: loads only the disjoint `train` split
   (`benchmarks/train_dataset.json` + `benchmarks/targets/solidity_train/`) and
   refuses any target present in `benchmark_dataset.json` or `TRUSTED_HARNESS_CONTRACTS`.
2. Multi-candidate group rollout collection (`G >= 4` per prompt across varying
   temperatures, e.g. `[0.2, 0.4, 0.7, 0.9]`) using injectable or default
   generator and verifier callables so unit tests run deterministically offline.
3. Persists BOTH successful (`EXPLOIT_CONFIRMED`, `+1.0`) and failed rollouts
   (`SAFE_RUN`, `RUNTIME_REVERT`, `COMPILATION_ERROR`, `GENERATION_FORMAT_ERROR`)
   while strictly excluding `INFRA_ERROR` from the persisted training dataset.
4. Enforces production GRPO provenance invariants:
   `dataset_partition="production"`, `dataset_split="train"`, `trainable=True`,
   `is_synthetic=False`, `token_provenance="model_generate"`, non-empty
   `prompt_text` and `generated_token_ids`.
5. Returns collection summary statistics including `diagnose_group_spread(...)`
   showing `informative_groups`.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from core.config import config
from core.evaluator import create_trajectory_record, evaluate_execution_trace
from core.evidence import HarnessVerdict, is_trusted_breach_verdict
from core.failure_digest import extract_failure_reason
from core.grpo_trainer import (
    diagnose_group_spread,
    group_rollouts_by_prompt,
    load_production_trajectories,
)
from core.llm_generator import build_analysis_prompt, build_refinement_prompt
from core.schemas import (
    ExecutionResult,
    ExploitPayload,
    ResultCategory,
    RLVRTrajectory,
    TargetProgram,
)
from sandbox.runner import (
    LOCAL_TRAIN_HARNESSES_DIR,
    LOCAL_TRUSTED_HARNESSES_DIR,
    TRAIN_TRUSTED_HARNESS_CONTRACTS,
    TRUSTED_HARNESS_CONTRACTS,
    run_payload_in_sandbox,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TRAIN_DATASET_PATH = REPO_ROOT / "benchmarks" / "train_dataset.json"
DEFAULT_BENCHMARK_DATASET_PATH = REPO_ROOT / "benchmarks" / "benchmark_dataset.json"
DEFAULT_ROLLOUT_TEMPERATURES: Tuple[float, ...] = (0.2, 0.4, 0.7, 0.9)

GeneratorFn = Callable[[TargetProgram, str, float, int], ExploitPayload]
VerifierFn = Callable[[TargetProgram, ExploitPayload], ExecutionResult]


@dataclass
class TrainRolloutCollectionResult:
    """Summary returned by `collect_train_rollouts`."""

    run_id: str
    trajectory_dir: str
    targets_processed: int
    candidates_generated: int
    persisted_count: int
    excluded_infra_count: int
    excluded_missing_tokens_count: int
    persisted_paths: List[str] = field(default_factory=list)
    category_counts: Dict[str, int] = field(default_factory=dict)
    group_spread: Dict[str, Any] = field(default_factory=dict)
    improved_by_refinement_count: int = 0


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_dataset_targets(dataset_path: Path) -> List[Dict[str, Any]]:
    with open(dataset_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    entries: List[Dict[str, Any]] = []
    for cls in data.get("classes", []):
        for entry in cls.get("targets", []):
            entries.append(entry)
    for entry in data.get("synthetic_controls", []):
        entries.append(entry)
    return entries


def _collect_test_isolation_index(
    benchmark_dataset_path: Path = DEFAULT_BENCHMARK_DATASET_PATH,
    test_solidity_dir: Path = Path(LOCAL_TRUSTED_HARNESSES_DIR),
) -> Tuple[set, set, set]:
    """Build sets of forbidden test target names, contract IDs, and source SHA-256s."""
    forbidden_names = set(TRUSTED_HARNESS_CONTRACTS.keys())
    forbidden_ids: set = set()
    forbidden_hashes: set = set()

    if benchmark_dataset_path.is_file():
        for entry in _load_dataset_targets(benchmark_dataset_path):
            if entry.get("target_name"):
                forbidden_names.add(str(entry["target_name"]))
            if entry.get("contract_id"):
                forbidden_ids.add(str(entry["contract_id"]))

    if test_solidity_dir.is_dir():
        for sol_file in test_solidity_dir.rglob("*.sol"):
            if sol_file.name.endswith("Harness.t.sol"):
                continue
            forbidden_hashes.add(_sha256_text(sol_file.read_text(encoding="utf-8")))

    return forbidden_names, forbidden_ids, forbidden_hashes


def validate_train_target_isolation(
    target: TargetProgram,
    contract_id: Optional[str] = None,
    benchmark_dataset_path: Path = DEFAULT_BENCHMARK_DATASET_PATH,
    test_solidity_dir: Path = Path(LOCAL_TRUSTED_HARNESSES_DIR),
) -> None:
    """
    Fail-closed guard ensuring a target belongs strictly to the disjoint train split
    and has zero overlap with the 16 benchmark test targets.
    """
    forbidden_names, forbidden_ids, forbidden_hashes = _collect_test_isolation_index(
        benchmark_dataset_path=benchmark_dataset_path,
        test_solidity_dir=test_solidity_dir,
    )

    if target.name in forbidden_names:
        raise ValueError(
            f"Data isolation violation: target '{target.name}' belongs to the test split / TRUSTED_HARNESS_CONTRACTS."
        )
    if contract_id and contract_id in forbidden_ids:
        raise ValueError(
            f"Data isolation violation: contract_id '{contract_id}' belongs to the test split."
        )
    if target.name not in TRAIN_TRUSTED_HARNESS_CONTRACTS:
        raise ValueError(
            f"Train allowlist violation: target '{target.name}' is not in TRAIN_TRUSTED_HARNESS_CONTRACTS."
        )
    source_hash = _sha256_text(target.source_code)
    if source_hash in forbidden_hashes:
        raise ValueError(
            f"Data isolation violation: source SHA-256 of '{target.name}' matches a test contract."
        )


def load_train_targets(
    train_dataset_path: Path = DEFAULT_TRAIN_DATASET_PATH,
    benchmark_dataset_path: Path = DEFAULT_BENCHMARK_DATASET_PATH,
    train_solidity_dir: Path = Path(LOCAL_TRAIN_HARNESSES_DIR),
    test_solidity_dir: Path = Path(LOCAL_TRUSTED_HARNESSES_DIR),
) -> List[TargetProgram]:
    """Load and isolation-validate all targets from `benchmarks/train_dataset.json`."""
    entries = _load_dataset_targets(train_dataset_path)
    targets: List[TargetProgram] = []

    for entry in entries:
        target_name = str(entry["target_name"])
        contract_id = entry.get("contract_id")
        rel_source = entry.get("source_file")
        if rel_source:
            candidate_path = REPO_ROOT / rel_source
            source_path = (
                candidate_path
                if candidate_path.is_file()
                else train_solidity_dir / f"{target_name}.sol"
            )
        else:
            source_path = train_solidity_dir / f"{target_name}.sol"
        if not source_path.is_file():
            raise FileNotFoundError(f"Train source contract missing: {source_path}")

        source_code = source_path.read_text(encoding="utf-8")
        invariant = entry.get("ground_truth_invariant")
        target = TargetProgram(
            name=target_name,
            source_code=source_code,
            language="solidity",
            invariants=[invariant] if invariant else [],
            slither_findings=[],
        )
        validate_train_target_isolation(
            target,
            contract_id=contract_id,
            benchmark_dataset_path=benchmark_dataset_path,
            test_solidity_dir=test_solidity_dir,
        )
        targets.append(target)

    return targets


def _default_verifier(target: TargetProgram, payload: ExploitPayload) -> ExecutionResult:
    """Verify a train candidate in the isolated Foundry sandbox using train harnesses."""
    return run_payload_in_sandbox(target, payload, allow_train_split=True)


def _ensure_temperatures(
    group_size: int,
    temperatures: Optional[Sequence[float]],
) -> List[float]:
    if group_size < 4:
        raise ValueError(f"GRPO group_size must be >= 4, got {group_size}")
    temps = list(temperatures) if temperatures else list(DEFAULT_ROLLOUT_TEMPERATURES)
    if not temps:
        temps = list(DEFAULT_ROLLOUT_TEMPERATURES)
    return [float(temps[idx % len(temps)]) for idx in range(group_size)]


def _normalize_payload(
    payload: ExploitPayload,
    target: TargetProgram,
    prompt_text: str,
    run_id: str,
    candidate_index: int,
) -> ExploitPayload:
    cand_id = payload.candidate_id or f"{run_id}_{target.name}_c{candidate_index}_{uuid.uuid4().hex[:6]}"
    effective_prompt = (
        payload.prompt_text
        if (payload.prompt_text and payload.prompt_text.strip())
        else prompt_text
    )
    return payload.model_copy(
        update={
            "target_name": target.name,
            "candidate_id": cand_id,
            "run_id": run_id,
            "candidate_index": candidate_index,
            "prompt_text": effective_prompt,
        }
    )


def _run_independent_replay_if_needed(
    target: TargetProgram,
    payload: ExploitPayload,
    exec_result: ExecutionResult,
    verifier_fn: VerifierFn,
) -> ExecutionResult:
    """
    Confirm reproducibility when an initial execution reports a trusted breach.
    If the caller's verifier already marked `reproducibility_confirmed=True`,
    preserve it without an extra verifier call.
    """
    trusted_breach = (
        exec_result.invariant_violated
        and exec_result.return_code == 0
        and exec_result.test_status == "Success"
        and not exec_result.cheatcode_detected
        and is_trusted_breach_verdict(exec_result.harness_verdict)
    )
    if not trusted_breach or exec_result.reproducibility_confirmed:
        return exec_result

    replay_res = verifier_fn(target, payload)
    if replay_res.category == ResultCategory.INFRA_ERROR:
        return exec_result.model_copy(
            update={
                "reproducibility_confirmed": False,
                "replay_error": replay_res.stderr or "Replay infrastructure failure",
            }
        )

    reproduced = (
        replay_res.invariant_violated
        and replay_res.return_code == 0
        and replay_res.test_status == "Success"
        and not replay_res.cheatcode_detected
        and is_trusted_breach_verdict(replay_res.harness_verdict)
    )
    return exec_result.model_copy(update={"reproducibility_confirmed": reproduced})


def _build_refinement_feedback(exec_result: ExecutionResult, fallback_reason: str) -> str:
    """Assemble concise, trace-grounded feedback for a refinement round."""
    digest = extract_failure_reason(
        stdout=exec_result.stdout,
        stderr=exec_result.stderr,
        revert_reason=exec_result.revert_reason,
        decoded_logs=exec_result.decoded_logs,
    )
    raw_err = (exec_result.stderr or exec_result.stdout or fallback_reason or "").strip()
    if digest and raw_err:
        combined = f"{digest}\n{raw_err}"
    else:
        combined = digest or raw_err or "Execution failed without diagnostic output."
    return combined[:1200]


def collect_train_rollouts(
    targets: Iterable[TargetProgram],
    trajectory_dir: str,
    generator_fn: GeneratorFn,
    verifier_fn: Optional[VerifierFn] = None,
    group_size: Optional[int] = None,
    temperatures: Optional[Sequence[float]] = None,
    run_id: Optional[str] = None,
    prompt_builder: Callable[[TargetProgram], str] = build_analysis_prompt,
    benchmark_dataset_path: Path = DEFAULT_BENCHMARK_DATASET_PATH,
    test_solidity_dir: Path = Path(LOCAL_TRUSTED_HARNESSES_DIR),
    model_id: Optional[str] = None,
    max_refinement_rounds: int = 0,
) -> TrainRolloutCollectionResult:
    """
    Collect `G >= 4` GRPO training rollouts per train target and persist eligible
    trajectories (`EXPLOIT_CONFIRMED`, `SAFE_RUN`, `RUNTIME_REVERT`,
    `COMPILATION_ERROR`, `GENERATION_FORMAT_ERROR`) to `trajectory_dir`.

    Strictly excludes `INFRA_ERROR` and enforces `dataset_partition="production"`,
    `dataset_split="train"`, `trainable=True`, `is_synthetic=False`, and
    `token_provenance="model_generate"`.
    """
    target_list = list(targets)
    for target in target_list:
        validate_train_target_isolation(
            target,
            benchmark_dataset_path=benchmark_dataset_path,
            test_solidity_dir=test_solidity_dir,
        )

    effective_group_size = group_size if group_size is not None else max(int(config.GRPO_GROUP_SIZE), 4)
    temp_schedule = _ensure_temperatures(effective_group_size, temperatures)
    active_verifier = verifier_fn or _default_verifier
    active_run_id = run_id or f"train_run_{uuid.uuid4().hex[:8]}"

    os.makedirs(trajectory_dir, exist_ok=True)

    candidates_generated = 0
    persisted_count = 0
    excluded_infra_count = 0
    excluded_missing_tokens_count = 0
    improved_by_refinement_count = 0
    persisted_paths: List[str] = []
    category_counts: Dict[str, int] = {}

    for target in target_list:
        prompt_text = prompt_builder(target)
        if not prompt_text or not prompt_text.strip():
            raise ValueError(f"prompt_text must be non-empty for target '{target.name}'")

        for cand_idx, temp in enumerate(temp_schedule):
            raw_payload = generator_fn(target, prompt_text, temp, cand_idx)
            payload = _normalize_payload(raw_payload, target, prompt_text, active_run_id, cand_idx)
            candidates_generated += 1

            if not payload.generated_token_ids or len(payload.generated_token_ids) == 0:
                excluded_missing_tokens_count += 1
                continue

            exec_result = active_verifier(target, payload)
            exec_result = _run_independent_replay_if_needed(
                target, payload, exec_result, active_verifier
            )
            verdict = evaluate_execution_trace(payload, exec_result)

            if (
                max_refinement_rounds > 0
                and verdict.category not in (ResultCategory.EXPLOIT_CONFIRMED, ResultCategory.INFRA_ERROR)
            ):
                best_payload = payload
                best_verdict = verdict
                best_exec = exec_result
                improved_in_refinement = False
                history: List[Dict[str, Any]] = []
                for round_idx in range(1, max_refinement_rounds + 1):
                    feedback = _build_refinement_feedback(best_exec, best_verdict.category.value)
                    history.append(
                        {
                            "candidate_id": best_payload.candidate_id,
                            "category": best_verdict.category.value,
                            "feedback": feedback,
                        }
                    )
                    refine_prompt = build_refinement_prompt(
                        target,
                        failed_code=best_payload.test_code or best_payload.raw_model_response or "",
                        error_feedback=feedback,
                        previous_failures=history,
                    )
                    raw_ref = generator_fn(target, refine_prompt, temp, cand_idx)
                    ref_payload = _normalize_payload(
                        raw_ref, target, refine_prompt, active_run_id, cand_idx
                    ).model_copy(update={"attempt_number": round_idx + 1})
                    if not ref_payload.generated_token_ids:
                        break
                    ref_exec = active_verifier(target, ref_payload)
                    ref_exec = _run_independent_replay_if_needed(
                        target, ref_payload, ref_exec, active_verifier
                    )
                    ref_verdict = evaluate_execution_trace(ref_payload, ref_exec)
                    if ref_verdict.category == ResultCategory.INFRA_ERROR:
                        break
                    if (
                        ref_verdict.category == ResultCategory.EXPLOIT_CONFIRMED
                        or ref_verdict.reward_score > best_verdict.reward_score
                    ):
                        best_payload = ref_payload
                        best_verdict = ref_verdict
                        best_exec = ref_exec
                        improved_in_refinement = True
                    if best_verdict.category == ResultCategory.EXPLOIT_CONFIRMED:
                        break
                payload = best_payload
                verdict = best_verdict
                exec_result = best_exec
                if improved_in_refinement:
                    improved_by_refinement_count += 1

            cat_name = verdict.category.value
            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

            # Strictly exclude INFRA_ERROR from persisted training rollouts
            if verdict.category == ResultCategory.INFRA_ERROR:
                excluded_infra_count += 1
                continue

            traj: RLVRTrajectory = create_trajectory_record(
                target=target,
                payload=payload,
                verdict=verdict,
                prompt_used=payload.prompt_text or prompt_text,
                dataset_split="train",
                dataset_partition="production",
                is_synthetic=False,
                token_provenance="model_generate",
                trainable=True,
                model_id=model_id,
            )

            filename = (
                f"{traj.trajectory_id}.json"
                if traj.trajectory_id.startswith("traj_")
                else f"traj_{traj.trajectory_id}.json"
            )
            out_path = os.path.join(trajectory_dir, filename)
            with open(out_path, "w", encoding="utf-8") as handle:
                json.dump(traj.model_dump(), handle, indent=2)
            persisted_paths.append(out_path)
            persisted_count += 1

    loaded_records = load_production_trajectories(trajectory_dir, target_split="train")
    groups = group_rollouts_by_prompt(loaded_records, group_size=effective_group_size)
    spread = diagnose_group_spread(groups)

    return TrainRolloutCollectionResult(
        run_id=active_run_id,
        trajectory_dir=trajectory_dir,
        targets_processed=len(target_list),
        candidates_generated=candidates_generated,
        persisted_count=persisted_count,
        excluded_infra_count=excluded_infra_count,
        excluded_missing_tokens_count=excluded_missing_tokens_count,
        persisted_paths=persisted_paths,
        category_counts=category_counts,
        group_spread=spread,
        improved_by_refinement_count=improved_by_refinement_count,
    )
