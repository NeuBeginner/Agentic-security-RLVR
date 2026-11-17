"""The retention rule of the trajectories (D28) - the producer's cleanup.

The persistent volume is a **billable object of its own**: the provider prices
it per GiB-month, separately from the compute of the container that writes to
it. A trajectory that stays on the volume is therefore paid for until it is
deleted. The plan (D28) prices three segments - the execution, the bounded
post-execution interval and the **retention** - and requires that the
retention ends in a **verified deletion**.

This module is that rule. It decides which trajectories are to be deleted, it
performs the deletion, and it measures the footprint of the trajectory
directory **before and after** the deletion, so that the deletion is measured
and not merely asserted.

Three selectors, all explicit:

* the **age** of a trajectory: a trajectory whose own timestamp is older than
  the retention window is expired and is deleted;
* an explicit **run id**: the trajectories of one (completed) run are deleted
  on demand;
* an explicit **path**: one named trajectory - the narrowest selector, used
  for a single test artefact.

The deletion runs on the volume through the provider's own volume API. It
starts **no container**: the compute of the deletion is zero, and the storage
that is freed is the storage that stops being paid for.

Nothing here changes a declaration of the cycle: the retention window is the
one the cost model already prices (``benchmarks.r1_estimator``), the volume is
the one the deployment already writes to (``core.config``), and no provider
call site is added - the procedure is a repository-side maintenance step, not
a dispatchable step.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

#: The seconds of a day.
SECONDS_PER_DAY = 86400.0

#: The retention interval: 30 days from the publication to the verified
#: deletion. It is the interval the cost model prices (D28), and it is the
#: interval this rule enforces.
DEFAULT_RETENTION_SEC = 30 * SECONDS_PER_DAY

#: The directory of the trajectories on the volume, relative to its root.
TRAJECTORY_DIR = "trajectories"

#: The prefix of the file name of a trajectory (``traj_<trajectory_id>.json``).
TRAJECTORY_PREFIX = "traj_"


@dataclasses.dataclass(frozen=True)
class Trajectory:
    """One trajectory on the volume."""

    #: The path of the file, relative to the root of the volume.
    path: str
    #: The size of the file in bytes.
    size_bytes: int
    #: The modification time the provider reports for the file.
    mtime: float
    #: The identifier of the trajectory, as the producer wrote it.
    trajectory_id: Optional[str] = None
    #: The run the trajectory belongs to, if the producer recorded one.
    run_id: Optional[str] = None
    #: The timestamp the trajectory itself carries, if it carries one.
    timestamp: Optional[float] = None
    #: Whether the producer marked the trajectory as finalized.
    finalized: Optional[bool] = None
    #: The reason the payload could not be read, if it could not be read.
    unreadable_reason: Optional[str] = None

    @property
    def age_sec(self) -> Optional[float]:
        """The age of the trajectory, from its own timestamp if it has one."""
        reference = self.timestamp if self.timestamp is not None else self.mtime
        if reference is None:
            return None
        return max(0.0, float(reference))


def trajectory_id_of(path: str) -> Optional[str]:
    """The identifier of the trajectory, as the name of its file carries it.

    The producer names the file ``traj_<trajectory_id>.json``; the identifier
    of a trajectory that does not follow that pattern is not guessed.
    """
    name = str(path).rsplit("/", 1)[-1]
    if not name.startswith(TRAJECTORY_PREFIX) or not name.endswith(".json"):
        return None
    return name[len(TRAJECTORY_PREFIX):-len(".json")]


def run_id_of(trajectory_id: Optional[str], payload: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """The run a trajectory belongs to.

    The producer records the run in the trajectory itself; a trajectory that
    predates that field carries the run in its identifier
    (``traj_run-default_89374b09`` -> ``run-default``).
    """
    if payload:
        recorded = payload.get("run_id")
        if isinstance(recorded, str) and recorded:
            return recorded
    if not trajectory_id:
        return None
    candidate = trajectory_id[len(TRAJECTORY_PREFIX):] if trajectory_id.startswith(TRAJECTORY_PREFIX) else trajectory_id
    if candidate.startswith("run-"):
        return candidate.rsplit("_", 1)[0]
    return None


def parse_trajectory(
    path: str,
    size_bytes: int,
    mtime: float,
    payload: Optional[Dict[str, Any]] = None,
    unreadable_reason: Optional[str] = None,
) -> Trajectory:
    """The trajectory of a file, as far as the file states it."""
    identifier = trajectory_id_of(path)
    timestamp = None
    finalized = None
    if payload:
        raw_timestamp = payload.get("timestamp")
        if isinstance(raw_timestamp, (int, float)):
            timestamp = float(raw_timestamp)
        if isinstance(payload.get("is_finalized"), bool):
            finalized = bool(payload["is_finalized"])
    return Trajectory(
        path=path,
        size_bytes=int(size_bytes),
        mtime=float(mtime),
        trajectory_id=identifier,
        run_id=run_id_of(identifier, payload),
        timestamp=timestamp,
        finalized=finalized,
        unreadable_reason=unreadable_reason,
    )


def is_expired(trajectory: Trajectory, now: float, retention_sec: float = DEFAULT_RETENTION_SEC) -> bool:
    """True when the trajectory is older than the retention window.

    The age is measured from the **trajectory's own** timestamp when it
    carries one, and from the provider's modification time otherwise: a
    trajectory that was written long ago and copied onto the volume today is
    still expired.
    """
    age = trajectory.age_sec
    if age is None:
        return False
    reference = trajectory.timestamp if trajectory.timestamp is not None else trajectory.mtime
    return (float(now) - float(reference)) > float(retention_sec)


def select_for_cleanup(
    trajectories: Sequence[Trajectory],
    now: float,
    retention_sec: float = DEFAULT_RETENTION_SEC,
    run_id: Optional[str] = None,
    paths: Optional[Iterable[str]] = None,
) -> List[Trajectory]:
    """The trajectories to be deleted, by the three selectors.

    A trajectory is selected when it is **expired**, or when it belongs to the
    given **run**, or when it is one of the given **paths**. Without a run and
    without paths, only the expired trajectories are selected.
    """
    wanted_paths = {str(path) for path in (paths or ())}
    selected: List[Trajectory] = []
    for trajectory in trajectories:
        expired = is_expired(trajectory, now, retention_sec)
        of_run = bool(run_id) and trajectory.run_id == run_id
        named = trajectory.path in wanted_paths
        if expired or of_run or named:
            selected.append(trajectory)
    return sorted(selected, key=lambda t: t.path)


def measure(volume: Any, directory: str = TRAJECTORY_DIR) -> Dict[str, Any]:
    """The footprint of the trajectory directory, as the provider reports it."""
    entries = []
    for entry in volume.listdir(directory):
        kind = getattr(getattr(entry, "type", None), "name", "FILE")
        entries.append(
            {
                "path": getattr(entry, "path", ""),
                "size": int(getattr(entry, "size", 0) or 0),
                "mtime": int(getattr(entry, "mtime", 0) or 0),
                "type": kind,
            }
        )
    files = [entry for entry in entries if str(entry["type"]).upper() == "FILE"]
    return {
        "directory": directory,
        "file_count": len(files),
        "total_bytes": sum(entry["size"] for entry in files),
        "entries": sorted(entries, key=lambda entry: entry["path"]),
    }


def read_trajectory_payload(volume: Any, path: str) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """The payload of a trajectory, and the reason it is unreadable.

    The payload is read from the provider's volume API. A trajectory whose
    payload cannot be read is **not** skipped: it is kept, it is measured by
    its modification time, and the reason is recorded.
    """
    try:
        raw = b"".join(volume.read_file(path))
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # the provider's own error, or a broken file
        return None, f"{type(exc).__name__}: {exc}"
    if not isinstance(payload, dict):
        return None, "the payload is not a JSON object"
    return payload, None


def run_retention_cleanup(
    volume: Any,
    now: float,
    retention_sec: float = DEFAULT_RETENTION_SEC,
    run_id: Optional[str] = None,
    paths: Optional[Iterable[str]] = None,
    directory: str = TRAJECTORY_DIR,
    dry_run: bool = False,
    payload_reader: Optional[Callable[[Any, str], tuple[Optional[Dict[str, Any]], Optional[str]]]] = None,
) -> Dict[str, Any]:
    """Delete the trajectories that the rule selects, and measure the result.

    The footprint of the directory is measured **before** the deletion and
    **again after** it, so the record carries the freed bytes - the deletion is
    verified, not asserted.
    """
    reader = payload_reader or read_trajectory_payload
    before = measure(volume, directory)

    trajectories: List[Trajectory] = []
    for entry in before["entries"]:
        if str(entry["type"]).upper() != "FILE":
            continue
        payload, reason = reader(volume, entry["path"])
        trajectories.append(
            parse_trajectory(
                entry["path"],
                entry["size"],
                float(entry["mtime"]),
                payload,
                reason,
            )
        )

    selected = select_for_cleanup(
        trajectories,
        now=now,
        retention_sec=retention_sec,
        run_id=run_id,
        paths=paths,
    )

    deleted: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for trajectory in selected:
        if dry_run:
            deleted.append({"path": trajectory.path, "size_bytes": trajectory.size_bytes})
            continue
        try:
            volume.remove_file(trajectory.path)
        except Exception as exc:  # the provider's own error
            failures.append(
                {"path": trajectory.path, "error": f"{type(exc).__name__}: {exc}"}
            )
            continue
        deleted.append({"path": trajectory.path, "size_bytes": trajectory.size_bytes})

    after = measure(volume, directory)
    return {
        "retention_sec": float(retention_sec),
        "run_id": run_id,
        "paths": sorted(str(path) for path in (paths or ())),
        "dry_run": bool(dry_run),
        "before": {"file_count": before["file_count"], "total_bytes": before["total_bytes"]},
        "after": {"file_count": after["file_count"], "total_bytes": after["total_bytes"]},
        "deleted": deleted,
        "deleted_bytes": sum(entry["size_bytes"] for entry in deleted),
        "freed_bytes": before["total_bytes"] - after["total_bytes"],
        "failures": failures,
        "kept": [
            {
                "path": trajectory.path,
                "size_bytes": trajectory.size_bytes,
                "run_id": trajectory.run_id,
                "trajectory_id": trajectory.trajectory_id,
                "timestamp": trajectory.timestamp,
                "unreadable_reason": trajectory.unreadable_reason,
            }
            for trajectory in trajectories
            if trajectory not in selected
        ],
        "trajectories": [
            {
                "path": trajectory.path,
                "size_bytes": trajectory.size_bytes,
                "run_id": trajectory.run_id,
                "trajectory_id": trajectory.trajectory_id,
                "timestamp": trajectory.timestamp,
                "finalized": trajectory.finalized,
                "unreadable_reason": trajectory.unreadable_reason,
            }
            for trajectory in sorted(trajectories, key=lambda t: t.path)
        ],
    }


__all__ = [
    "DEFAULT_RETENTION_SEC",
    "SECONDS_PER_DAY",
    "TRAJECTORY_DIR",
    "TRAJECTORY_PREFIX",
    "Trajectory",
    "is_expired",
    "measure",
    "parse_trajectory",
    "read_trajectory_payload",
    "run_id_of",
    "run_retention_cleanup",
    "select_for_cleanup",
    "trajectory_id_of",
]
