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
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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


def _validate_bounds(max_targets: int, group_size: int, max_new_tokens: int) -> None:
    """Enforce hard PoC bounds before any execution."""
    if not (1 <= max_targets <= 10):
        raise ValueError(f"--max-targets must be between 1 and 10, got {max_targets}")
    if not (4 <= group_size <= 8):
        raise ValueError(f"--group-size must be between 4 and 8, got {group_size}")
    if max_new_tokens <= 0:
        raise ValueError(f"--max-new-tokens must be positive, got {max_new_tokens}")


def run_dry_run(
    stage: str,
    max_targets: int,
    group_size: int,
    max_new_tokens: int,
    model_id: str,
) -> Dict[str, Any]:
    """Validate local train targets ($0) and return the execution plan."""
    _validate_bounds(max_targets=max_targets, group_size=group_size, max_new_tokens=max_new_tokens)

    all_targets = load_train_targets()
    for target in all_targets:
        validate_train_target_isolation(target)

    selected = all_targets[:max_targets]
    return {
        "mode": "dry-run",
        "cost_usd": 0.0,
        "app_name": APP_NAME,
        "stage": stage,
        "gpu_type": config.GRPO_POC_GPU_TYPE,
        "model_id": model_id,
        "trajectory_dir": config.GRPO_POC_TRAJECTORY_DIR,
        "checkpoint_dir": config.GRPO_POC_CHECKPOINT_DIR,
        "training_blocked": is_training_blocked(config),
        "total_train_targets_validated": len(all_targets),
        "selected_target_count": len(selected),
        "selected_targets": [t.name for t in selected],
        "group_size": group_size,
        "max_new_tokens": max_new_tokens,
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
) -> Dict[str, Any]:
    """Execute the approved live GRPO PoC stage on Modal."""
    _assert_authorised()
    _validate_bounds(max_targets=max_targets, group_size=group_size, max_new_tokens=max_new_tokens)

    if stage == "train" and is_training_blocked(config):
        raise RuntimeError(
            "FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED. "
            "GRPO training stage is strictly blocked on the client before contacting Modal."
        )

    import modal  # noqa: E402 — imported ONLY after fail-closed authorisation gates

    results: Dict[str, Any] = {
        "app_name": APP_NAME,
        "stage": stage,
        "gpu_type": config.GRPO_POC_GPU_TYPE,
        "model_id": model_id,
        "trajectory_dir": config.GRPO_POC_TRAJECTORY_DIR,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    if stage in ("collect", "collect-and-diagnose"):
        collect_fn = modal.Function.from_name(APP_NAME, "poc_collect_train_rollouts")
        results["collect"] = collect_fn.remote(
            model_id=model_id,
            max_targets=max_targets,
            group_size=group_size,
            max_new_tokens=max_new_tokens,
            trajectory_dir=config.GRPO_POC_TRAJECTORY_DIR,
        )

    if stage in ("diagnose", "collect-and-diagnose"):
        diag_fn = modal.Function.from_name(APP_NAME, "poc_diagnostic_grpo_forward")
        results["diagnose"] = diag_fn.remote(
            model_id=model_id,
            batch_group_size=group_size,
            trajectory_dir=config.GRPO_POC_TRAJECTORY_DIR,
        )

    if stage == "train":
        train_fn = modal.Function.from_name(APP_NAME, "poc_train_grpo")
        results["train"] = train_fn.remote(
            model_id=model_id,
            num_steps=num_steps,
            learning_rate=learning_rate,
            batch_group_size=group_size,
            trajectory_dir=config.GRPO_POC_TRAJECTORY_DIR,
            checkpoint_dir=config.GRPO_POC_CHECKPOINT_DIR,
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
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
