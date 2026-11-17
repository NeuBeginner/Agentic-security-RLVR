"""The cleanup procedure of the trajectories (D28) - the command line.

The persistent volume of this workflow is a **billable object of its own**:
the provider prices it per GiB-month, and a trajectory stays on it until it is
deleted. The plan (D28) prices the retention as the third segment of the
storage of a step and requires that the retention ends in a **verified
deletion**.

This command performs that deletion and **measures** the result: the footprint
of the trajectory directory is taken before the deletion and again after it,
and the freed bytes are the difference.

The deletion runs on the volume through the provider's own volume API. It
starts **no container** - the compute of the deletion is zero, and the storage
that is freed is the storage that stops being paid for.

Examples::

    # what would be deleted (nothing is written)
    python -m benchmarks.run_retention_cleanup --dry-run

    # the trajectories of one completed run
    python -m benchmarks.run_retention_cleanup --run-id run-default

    # one named trajectory
    python -m benchmarks.run_retention_cleanup --path trajectories/traj_pilot-R3b.json
"""

from __future__ import annotations

import argparse
import json
import time
from typing import List, Optional, Sequence

from core.config import config
from core.r1_retention import (
    DEFAULT_RETENTION_SEC,
    TRAJECTORY_DIR,
    run_retention_cleanup,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benchmarks.run_retention_cleanup",
        description="Delete the expired trajectories of the persistent volume and measure the result.",
    )
    parser.add_argument(
        "--volume",
        default=config.MODEL_VOLUME_NAME,
        help="the volume to clean (default: the volume of the workflow)",
    )
    parser.add_argument(
        "--directory",
        default=TRAJECTORY_DIR,
        help="the directory of the trajectories, relative to the root of the volume",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="delete the trajectories of this run",
    )
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="delete this trajectory (repeatable)",
    )
    parser.add_argument(
        "--retention-sec",
        type=float,
        default=DEFAULT_RETENTION_SEC,
        help=f"the retention window in seconds (default: {DEFAULT_RETENTION_SEC})",
    )
    parser.add_argument(
        "--now",
        type=float,
        default=None,
        help="the moment the age is measured against (default: now)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be deleted, and delete nothing",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the record as JSON (the default)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    import modal

    volume = modal.Volume.from_name(args.volume)
    record = run_retention_cleanup(
        volume,
        now=args.now if args.now is not None else time.time(),
        retention_sec=args.retention_sec,
        run_id=args.run_id,
        paths=args.path or None,
        directory=args.directory,
        dry_run=bool(args.dry_run),
    )
    record["volume"] = args.volume
    print(json.dumps(record, indent=2, default=str))
    return 1 if record.get("failures") else 0


if __name__ == "__main__":
    raise SystemExit(main())
