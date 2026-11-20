"""
benchmarks/run_grpo_poc.py
==========================

Fail-closed local driver for the isolated L4 GRPO PoC Modal application
(``modal_grpo_poc_app.py``).

Refused by default: requires ``AEGIS_APPROVE_GRPO_POC=1`` for any live Modal
call. Supports ``--dry-run`` ($0) to validate local train-target isolation and
print the execution plan without importing or contacting Modal.
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.config import config, is_training_blocked  # noqa: E402
from core.train_rollout_collector import (  # noqa: E402
    load_train_targets,
    validate_train_target_isolation,
)

APP_NAME = "aegis-rlvr-grpo-poc"
APPROVAL_ENV_VAR = "AEGIS_APPROVE_GRPO_POC"
APPROVAL_VALUES = ("1", "true", "yes")
DEFAULT_OUTPUT_DIR = "benchmarks/evidence/grpo_poc"
VALID_STAGES = ("collect-and-diagnose", "collect", "diagnose", "train")


class GrpoPocNotAuthorised(RuntimeError):
    """The live GRPO PoC invocation was refused: it is not authorised."""


def _assert_authorised() -> None:
    """Refuse any live Modal invocation unless AEGIS_APPROVE_GRPO_POC is explicitly set."""
    value = os.environ.get(APPROVAL_ENV_VAR, "").strip().lower()
    if value in APPROVAL_VALUES:
        return
    raise GrpoPocNotAuthorised(
        "the live GRPO PoC invocation is refused: this app is not part of the "
        "R1 evidence-regeneration workflow and requires explicit maintainer approval. "
        f"Set {APPROVAL_ENV_VAR}=1 only with an explicit budget approval."
    )


def _validate_bounds(
    max_targets: int,
    group_size: int,
    max_new_tokens: int,
    num_steps: int = 2,
    learning_rate: float = 5e-6,
) -> None:
    """Enforce hard PoC bounds before any execution."""
    if not (1 <= max_targets <= 10):
        raise ValueError(f"--max-targets must be between 1 and 10, got {max_targets}")
    if not (4 <= group_size <= 8):
        raise ValueError(f"--group-size must be between 4 and 8, got {group_size}")
    if max_new_tokens <= 0:
        raise ValueError(f"--max-new-tokens must be positive, got {max_new_tokens}")
    if num_steps <= 0:
        raise ValueError(f"--num-steps must be positive, got {num_steps}")
    if learning_rate <= 0:
        raise ValueError(f"--learning-rate must be positive, got {learning_rate}")


def _parse_target_names(raw: Optional[Sequence[str] | str]) -> Optional[List[str]]:
    """Parse comma-separated or sequence target names into a deduplicated list."""
    if raw is None:
        return None
    if isinstance(raw, str):
        items = [part.strip() for part in raw.split(",") if part.strip()]
    else:
        items = [str(part).strip() for part in raw if str(part).strip()]
    return items or None


def _select_and_validate_train_targets(
    max_targets: int,
    target_names: Optional[List[str]] = None,
):
    """Load train targets, enforce zero test-split overlap, and apply selection."""
    all_targets = load_train_targets()
    for target in all_targets:
        validate_train_target_isolation(target)

    if target_names:
        by_name = {t.name: t for t in all_targets}
        unknown = [name for name in target_names if name not in by_name]
        if unknown:
            raise ValueError(
                f"Unknown or non-train target_names requested: {unknown}. "
                f"Available train targets: {sorted(by_name)}"
            )
        selected = [by_name[name] for name in target_names]
    else:
        selected = all_targets[:max_targets]

    return all_targets, selected


def run_dry_run(
    stage: str,
    max_targets: int,
    group_size: int,
    max_new_tokens: int,
    model_id: str,
    target_names: Optional[Sequence[str] | str] = None,
    run_id: Optional[str] = None,
    num_steps: int = 2,
    learning_rate: float = 5e-6,
    adapter_path: Optional[str] = None,
    informative_only: bool = False,
) -> Dict[str, Any]:
    """Validate local train targets ($0) and return the execution plan."""
    parsed_names = _parse_target_names(target_names)
    _validate_bounds(
        max_targets=max_targets,
        group_size=group_size,
        max_new_tokens=max_new_tokens,
        num_steps=num_steps,
        learning_rate=learning_rate,
    )

    all_targets, selected = _select_and_validate_train_targets(
        max_targets=max_targets,
        target_names=parsed_names,
    )
    resolved_traj_dir = (
        posixpath.join(config.GRPO_POC_TRAJECTORY_DIR.rstrip("/"), run_id)
        if run_id
        else config.GRPO_POC_TRAJECTORY_DIR
    )
    resolved_ckpt_dir = (
        posixpath.join(config.GRPO_POC_CHECKPOINT_DIR.rstrip("/"), run_id)
        if run_id
        else config.GRPO_POC_CHECKPOINT_DIR
    )
    return {
        "mode": "dry-run",
        "cost_usd": 0.0,
        "app_name": APP_NAME,
        "stage": stage,
        "gpu_type": config.GRPO_POC_GPU_TYPE,
        "model_id": model_id,
        "adapter_path": adapter_path,
        "informative_only": informative_only,
        "run_id": run_id,
        "trajectory_dir": resolved_traj_dir,
        "checkpoint_dir": resolved_ckpt_dir,
        "training_blocked": is_training_blocked(config),
        "total_train_targets_validated": len(all_targets),
        "selected_target_count": len(selected),
        "selected_targets": [t.name for t in selected],
        "target_names": parsed_names,
        "group_size": group_size,
        "max_new_tokens": max_new_tokens,
        "num_steps": num_steps,
        "learning_rate": learning_rate,
    }


def run_live_poc(
    stage: str,
    max_targets: int = 4,
    group_size: int = 4,
    max_new_tokens: int = 1536,
    model_id: str = config.GRPO_BASE_MODEL,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    num_steps: int = 2,
    learning_rate: float = 5e-6,
    target_names: Optional[Sequence[str] | str] = None,
    run_id: Optional[str] = None,
    adapter_path: Optional[str] = None,
    informative_only: bool = False,
) -> Dict[str, Any]:
    """Execute the approved live GRPO PoC stage on Modal."""
    _assert_authorised()
    parsed_names = _parse_target_names(target_names)
    _validate_bounds(
        max_targets=max_targets,
        group_size=group_size,
        max_new_tokens=max_new_tokens,
        num_steps=num_steps,
        learning_rate=learning_rate,
    )

    if stage == "train" and is_training_blocked(config):
        raise RuntimeError(
            "FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED. "
            "GRPO training stage is strictly blocked on the client before contacting Modal."
        )

    if parsed_names is not None:
        _select_and_validate_train_targets(max_targets=max_targets, target_names=parsed_names)

    import modal  # noqa: E402 — imported ONLY after fail-closed authorisation gates

    active_ckpt_dir = (
        posixpath.join(config.GRPO_POC_CHECKPOINT_DIR.rstrip("/"), run_id)
        if run_id
        else config.GRPO_POC_CHECKPOINT_DIR
    )

    results: Dict[str, Any] = {
        "app_name": APP_NAME,
        "stage": stage,
        "gpu_type": config.GRPO_POC_GPU_TYPE,
        "model_id": model_id,
        "adapter_path": adapter_path,
        "informative_only": informative_only,
        "run_id": run_id,
        "trajectory_dir": config.GRPO_POC_TRAJECTORY_DIR,
        "checkpoint_dir": active_ckpt_dir,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    if stage in ("collect", "collect-and-diagnose"):
        collect_fn = modal.Function.from_name(APP_NAME, "poc_collect_train_rollouts")
        results["collect"] = collect_fn.remote(
            model_id=model_id,
            max_targets=max_targets,
            group_size=group_size,
            max_new_tokens=max_new_tokens,
            run_id=run_id,
            trajectory_dir=config.GRPO_POC_TRAJECTORY_DIR,
            target_names=parsed_names,
            adapter_path=adapter_path,
        )

    active_traj_dir = config.GRPO_POC_TRAJECTORY_DIR
    if stage == "collect-and-diagnose" and isinstance(results.get("collect"), dict):
        active_traj_dir = results["collect"].get("trajectory_dir") or config.GRPO_POC_TRAJECTORY_DIR
    elif run_id:
        active_traj_dir = posixpath.join(config.GRPO_POC_TRAJECTORY_DIR.rstrip("/"), run_id)
    results["trajectory_dir"] = active_traj_dir

    if stage in ("diagnose", "collect-and-diagnose"):
        diag_fn = modal.Function.from_name(APP_NAME, "poc_diagnostic_grpo_forward")
        results["diagnose"] = diag_fn.remote(
            model_id=model_id,
            batch_group_size=group_size,
            trajectory_dir=active_traj_dir,
        )

    if stage == "train":
        train_fn = modal.Function.from_name(APP_NAME, "poc_train_grpo")
        if hasattr(train_fn, "with_options") and hasattr(getattr(modal, "Secret", None), "from_dict"):
            train_fn = train_fn.with_options(
                secrets=[
                    modal.Secret.from_dict(
                        {
                            "TRAINING_STATUS": os.environ["TRAINING_STATUS"],
                            "TRAINING_BLOCKED": os.environ["TRAINING_BLOCKED"],
                        }
                    )
                ]
            )
        results["train"] = train_fn.remote(
            model_id=model_id,
            num_steps=num_steps,
            learning_rate=learning_rate,
            batch_group_size=group_size,
            trajectory_dir=active_traj_dir,
            checkpoint_dir=active_ckpt_dir,
            informative_only=informative_only,
        )

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact_file = out_path / f"poc_{stage}_{ts}.json"
    artifact_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    results["artifact_file"] = str(artifact_file)
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed driver for the isolated L4 GRPO PoC Modal application."
    )
    parser.add_argument(
        "--stage",
        choices=VALID_STAGES,
        default="collect-and-diagnose",
        help="PoC stage to execute (default: collect-and-diagnose).",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=4,
        help="Maximum number of train targets to process (default: 4, cap: 10).",
    )
    parser.add_argument(
        "--group-size",
        type=int,
        default=4,
        help="Number of rollouts per target group (default: 4, range: 4..8).",
    )
    parser.add_argument(
        "--max-new-tokens",
        type=int,
        default=1536,
        help="Maximum new tokens per generation (default: 1536).",
    )
    parser.add_argument(
        "--model-id",
        default=config.GRPO_BASE_MODEL,
        help=f"Base model ID (default: {config.GRPO_BASE_MODEL}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Strictly $0 local validation of train targets and plan output without Modal.",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to store live PoC JSON artifacts (default: {DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--target-names",
        default=None,
        help="Optional comma-separated list of disjoint train target names.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional run_id for per-run trajectory directory isolation.",
    )
    parser.add_argument(
        "--num-steps",
        type=int,
        default=2,
        help="Number of LoRA GRPO steps for --stage train (default: 2).",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=5e-6,
        help="Learning rate for --stage train (default: 5e-6).",
    )
    parser.add_argument(
        "--adapter-path",
        default=None,
        help="Optional LoRA adapter checkpoint path on Modal volume for collect evaluation.",
    )
    parser.add_argument(
        "--informative-only",
        action="store_true",
        help="Filter out degenerate rollout groups before --stage train.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dry_run:
        plan = run_dry_run(
            stage=args.stage,
            max_targets=args.max_targets,
            group_size=args.group_size,
            max_new_tokens=args.max_new_tokens,
            model_id=args.model_id,
            target_names=args.target_names,
            run_id=args.run_id,
            num_steps=args.num_steps,
            learning_rate=args.learning_rate,
            adapter_path=args.adapter_path,
            informative_only=args.informative_only,
        )
        print(json.dumps(plan, indent=2))
        return 0

    res = run_live_poc(
        stage=args.stage,
        max_targets=args.max_targets,
        group_size=args.group_size,
        max_new_tokens=args.max_new_tokens,
        model_id=args.model_id,
        output_dir=args.output_dir,
        num_steps=args.num_steps,
        learning_rate=args.learning_rate,
        target_names=args.target_names,
        run_id=args.run_id,
        adapter_path=args.adapter_path,
        informative_only=args.informative_only,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
