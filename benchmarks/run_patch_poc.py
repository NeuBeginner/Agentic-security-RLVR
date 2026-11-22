"""
benchmarks/run_patch_poc.py
===========================

Fail-closed CLI driver for E2E Dual-Loop Red->Blue LLM patch verification
on the isolated Modal L4 PoC app (`aegis-rlvr-grpo-poc`).
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

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.config import config  # noqa: E402
from sandbox.patch_runner import TRAIN_FUNCTIONAL_TESTS  # noqa: E402

APP_NAME = "aegis-rlvr-grpo-poc"
DEFAULT_OUTPUT_DIR = "benchmarks/evidence/dual_loop_poc"
DEFAULT_PILOT_TARGETS = ("TrainAdminTreasury", "TrainShareVault", "TrainUninitializedVault")
DEFAULT_RED_TRAJ_DIRS = (
    "/vol/models/trajectories_grpo_poc/poc_40t_dev_post_r1",
    "/vol/models/trajectories_grpo_poc/poc_40t_train32",
)


def _parse_csv(raw: Optional[Sequence[str] | str]) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [p.strip() for p in raw.split(",") if p.strip()]
    return [str(p).strip() for p in raw if str(p).strip()]


def _validate_patch_poc_bounds(
    *,
    target_names: Sequence[str],
    group_size: int,
    max_refinement_rounds: int,
    max_new_tokens: int,
) -> List[str]:
    if not target_names:
        raise ValueError("At least one target_name must be provided.")
    unknown = [t for t in target_names if t not in TRAIN_FUNCTIONAL_TESTS]
    if unknown:
        raise ValueError(
            f"Targets {unknown} do not have registered functional regression suites. "
            f"Available: {sorted(TRAIN_FUNCTIONAL_TESTS)}"
        )
    if not (1 <= group_size <= 4):
        raise ValueError(f"--group-size must be between 1 and 4, got {group_size}")
    if not (0 <= max_refinement_rounds <= 2):
        raise ValueError(f"--max-refinement-rounds must be between 0 and 2, got {max_refinement_rounds}")
    if not (256 <= max_new_tokens <= 2048):
        raise ValueError(f"--max-new-tokens must be between 256 and 2048, got {max_new_tokens}")
    return list(target_names)


def _assert_authorised() -> None:
    if os.environ.get("AEGIS_APPROVE_GRPO_POC") != "1":
        raise PermissionError(
            "Fail-closed: set AEGIS_APPROVE_GRPO_POC=1 to execute live Modal patch PoC calls."
        )


def run_dry_run(
    *,
    target_names: Optional[Sequence[str] | str] = None,
    red_trajectory_dirs: Optional[Sequence[str] | str] = None,
    model_id: str = "Qwen/Qwen3-4B-Instruct-2507",
    adapter_path: Optional[str] = None,
    group_size: int = 4,
    max_refinement_rounds: int = 1,
    max_new_tokens: int = 1536,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate pilot targets and bounds locally for $0.00."""
    parsed_targets = _parse_csv(target_names) or list(DEFAULT_PILOT_TARGETS)
    validated_targets = _validate_patch_poc_bounds(
        target_names=parsed_targets,
        group_size=group_size,
        max_refinement_rounds=max_refinement_rounds,
        max_new_tokens=max_new_tokens,
    )
    red_dirs = _parse_csv(red_trajectory_dirs) or list(DEFAULT_RED_TRAJ_DIRS)
    resolved_out = posixpath.join("/vol/models/dual_loop_poc", run_id) if run_id else "/vol/models/dual_loop_poc"
    return {
        "mode": "dry-run",
        "cost_usd": 0.0,
        "app_name": APP_NAME,
        "gpu_type": config.GRPO_POC_GPU_TYPE,
        "model_id": model_id,
        "adapter_path": adapter_path,
        "run_id": run_id,
        "volume_output_dir": resolved_out,
        "target_names": validated_targets,
        "red_trajectory_dirs": red_dirs,
        "group_size": group_size,
        "max_refinement_rounds": max_refinement_rounds,
        "max_new_tokens": max_new_tokens,
    }


def run_live_patch_poc(
    *,
    target_names: Optional[Sequence[str] | str] = None,
    red_trajectory_dirs: Optional[Sequence[str] | str] = None,
    model_id: str = "Qwen/Qwen3-4B-Instruct-2507",
    adapter_path: Optional[str] = None,
    group_size: int = 4,
    max_refinement_rounds: int = 1,
    max_new_tokens: int = 1536,
    run_id: Optional[str] = None,
    output_dir: str = DEFAULT_OUTPUT_DIR,
) -> Dict[str, Any]:
    """Execute live Dual-Loop Red->Blue LLM patch verification on Modal L4."""
    _assert_authorised()
    parsed_targets = _parse_csv(target_names) or list(DEFAULT_PILOT_TARGETS)
    validated_targets = _validate_patch_poc_bounds(
        target_names=parsed_targets,
        group_size=group_size,
        max_refinement_rounds=max_refinement_rounds,
        max_new_tokens=max_new_tokens,
    )
    red_dirs = _parse_csv(red_trajectory_dirs) or list(DEFAULT_RED_TRAJ_DIRS)

    import modal  # noqa: E402 — imported ONLY after fail-closed authorisation

    fn = modal.Function.from_name(APP_NAME, "poc_run_dual_loop_patches")
    remote_res = fn.remote(
        model_id=model_id,
        target_names=validated_targets,
        red_trajectory_dirs=red_dirs,
        run_id=run_id,
        group_size=group_size,
        max_new_tokens=max_new_tokens,
        max_refinement_rounds=max_refinement_rounds,
        adapter_path=adapter_path,
    )

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"dual_loop_patch_{run_id or 'run'}_{ts}.json"
    out_path.write_text(json.dumps(remote_res, indent=2) + "\n", encoding="utf-8")
    remote_res["artifact_file"] = str(out_path)
    return remote_res


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed Dual-Loop Patch PoC driver (Modal L4)")
    parser.add_argument("--dry-run", action="store_true", help="Validate locally and print plan ($0.00).")
    parser.add_argument("--target-names", default=",".join(DEFAULT_PILOT_TARGETS))
    parser.add_argument("--red-trajectory-dirs", default=",".join(DEFAULT_RED_TRAJ_DIRS))
    parser.add_argument("--model-id", default="Qwen/Qwen3-4B-Instruct-2507")
    parser.add_argument("--adapter-path", default=None)
    parser.add_argument("--group-size", type=int, default=4)
    parser.add_argument("--max-refinement-rounds", type=int, default=1)
    parser.add_argument("--max-new-tokens", type=int, default=1536)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.dry_run:
        plan = run_dry_run(
            target_names=args.target_names,
            red_trajectory_dirs=args.red_trajectory_dirs,
            model_id=args.model_id,
            adapter_path=args.adapter_path,
            group_size=args.group_size,
            max_refinement_rounds=args.max_refinement_rounds,
            max_new_tokens=args.max_new_tokens,
            run_id=args.run_id,
        )
        print(json.dumps(plan, indent=2))
        return 0

    res = run_live_patch_poc(
        target_names=args.target_names,
        red_trajectory_dirs=args.red_trajectory_dirs,
        model_id=args.model_id,
        adapter_path=args.adapter_path,
        group_size=args.group_size,
        max_refinement_rounds=args.max_refinement_rounds,
        max_new_tokens=args.max_new_tokens,
        run_id=args.run_id,
        output_dir=args.output_dir,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
