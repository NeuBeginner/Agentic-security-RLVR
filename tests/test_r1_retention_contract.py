"""The contract of the retention rule of the trajectories (D28).

The proofs this file carries:

* the retention window is the interval the cost model prices - the model and
  the cleanup delete the **same** interval;
* a trajectory is expired when its **own** timestamp is older than the
  window, and the provider's modification time is the fallback;
* the selectors are explicit: the age, a **run id** and a named **path**;
* the cleanup deletes what it selects, deletes nothing else, and **measures**
  the footprint of the directory before and after the deletion.

Everything here is local: no test performs a provider call, a deployment, a
volume operation or a model download. The provider's volume is a double.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from core import r1_retention as retention


# --------------------------------------------------------------------------------------
# the doubles
# --------------------------------------------------------------------------------------


class _Entry:
    def __init__(self, path: str, size: int, mtime: float, type_: str = "FILE") -> None:
        self.path = path
        self.size = size
        self.mtime = mtime
        self.type = type_


class _FakeVolume:
    """A volume double: a listing, a payload per file and the deletions."""

    def __init__(self, files: Dict[str, bytes], mtimes: Optional[Dict[str, float]] = None) -> None:
        self.files = dict(files)
        self.mtimes = dict(mtimes or {})
        self.removed: List[str] = []

    def listdir(self, directory: str) -> List[_Entry]:
        entries = []
        for path, content in sorted(self.files.items()):
            if not path.startswith(directory.rstrip("/") + "/"):
                continue
            entries.append(_Entry(path, len(content), self.mtimes.get(path, 0.0)))
        return entries

    def read_file(self, path: str):
        content = self.files[path]
        yield content

    def remove_file(self, path: str) -> None:
        if path not in self.files:
            raise FileNotFoundError(path)
        del self.files[path]
        self.removed.append(path)


def _trajectory(trajectory_id: str, payload: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    return {
        "trajectory_id": trajectory_id,
        "candidate_id": trajectory_id,
        "run_id": "run-default",
        "timestamp": 1794175089.042254,
        "is_finalized": True,
        "replay_status": "CONFIRMED",
        **(payload or {}),
    }


# --------------------------------------------------------------------------------------
# the window is the one the cost model prices
# --------------------------------------------------------------------------------------


def test_the_retention_window_is_the_interval_the_cost_model_prices():
    """The model prices the very interval the cleanup enforces."""
    from benchmarks import r1_estimator

    assert retention.DEFAULT_RETENTION_SEC == 30 * 86400.0
    assert r1_estimator.DEFAULT_RETENTION_SEC == retention.DEFAULT_RETENTION_SEC


# --------------------------------------------------------------------------------------
# the expiry
# --------------------------------------------------------------------------------------


def test_a_trajectory_older_than_the_window_is_expired():
    trajectory = retention.parse_trajectory(
        "trajectories/traj_a.json", 10, mtime=0.0, payload=_trajectory("a", {"timestamp": 1000.0})
    )
    assert retention.is_expired(trajectory, now=1000.0 + retention.DEFAULT_RETENTION_SEC + 1.0) is True


def test_a_trajectory_inside_the_window_is_kept():
    trajectory = retention.parse_trajectory(
        "trajectories/traj_a.json", 10, mtime=0.0, payload=_trajectory("a", {"timestamp": 1000.0})
    )
    assert retention.is_expired(trajectory, now=1000.0 + retention.DEFAULT_RETENTION_SEC - 1.0) is False


def test_the_expiry_is_measured_from_the_trajectory_itself():
    """A trajectory that was written long ago and copied onto the volume today is expired."""
    trajectory = retention.parse_trajectory(
        "trajectories/traj_a.json", 10, mtime=9_000_000.0, payload=_trajectory("a", {"timestamp": 1000.0})
    )
    assert trajectory.timestamp == 1000.0
    assert retention.is_expired(trajectory, now=9_000_000.0) is True


def test_the_modification_time_is_the_fallback_of_the_expiry():
    trajectory = retention.parse_trajectory(
        "trajectories/traj_a.json", 10, mtime=1000.0, payload=None
    )
    assert trajectory.timestamp is None
    assert retention.is_expired(trajectory, now=1000.0 + retention.DEFAULT_RETENTION_SEC + 1.0) is True


def test_the_trajectory_id_is_parsed_from_the_name_of_the_file():
    assert retention.trajectory_id_of("trajectories/traj_pilot-R3b.json") == "pilot-R3b"
    assert retention.trajectory_id_of("trajectories/other.json") is None
    assert retention.trajectory_id_of("trajectories/traj_a.txt") is None


def test_the_run_id_is_read_from_the_payload_and_from_the_identifier():
    payload = _trajectory("a", {"run_id": "run-42"})
    assert retention.run_id_of("a", payload) == "run-42"
    # A trajectory that predates the field carries the run in its identifier.
    assert retention.run_id_of("traj_run-default_89374b09") == "run-default"
    assert retention.run_id_of("pilot-R3b") is None


# --------------------------------------------------------------------------------------
# the selectors
# --------------------------------------------------------------------------------------


def _expired(path: str, size: int = 10) -> Any:
    return retention.parse_trajectory(
        path, size, mtime=0.0, payload=_trajectory(retention.trajectory_id_of(path), {"timestamp": 0.0})
    )


def _fresh(path: str, size: int = 10) -> Any:
    return retention.parse_trajectory(
        path,
        size,
        mtime=10_000_000.0,
        payload=_trajectory(retention.trajectory_id_of(path), {"timestamp": 10_000_000.0}),
    )


def test_only_the_expired_trajectories_are_selected_without_a_selector():
    trajectories = [_expired("trajectories/traj_old.json"), _fresh("trajectories/traj_new.json")]
    selected = retention.select_for_cleanup(trajectories, now=10_000_000.0)
    assert [t.path for t in selected] == ["trajectories/traj_old.json"]


def test_the_run_selector_deletes_the_trajectories_of_that_run_only():
    trajectories = [
        retention.parse_trajectory(
            "trajectories/traj_run-default_1.json", 10, 0.0, _trajectory("traj_run-default_1", {"run_id": "run-default"})
        ),
        retention.parse_trajectory(
            "trajectories/traj_run-other_2.json", 10, 0.0, _trajectory("traj_run-other_2", {"run_id": "run-other"})
        ),
    ]
    selected = retention.select_for_cleanup(trajectories, now=10_000.0, run_id="run-default")
    assert [t.path for t in selected] == ["trajectories/traj_run-default_1.json"]


def test_the_path_selector_deletes_the_named_trajectory():
    trajectories = [_fresh("trajectories/traj_pilot-R3b.json"), _fresh("trajectories/traj_other.json")]
    selected = retention.select_for_cleanup(
        trajectories, now=10_000.0, paths=["trajectories/traj_pilot-R3b.json"]
    )
    assert [t.path for t in selected] == ["trajectories/traj_pilot-R3b.json"]


# --------------------------------------------------------------------------------------
# the cleanup
# --------------------------------------------------------------------------------------


def test_the_cleanup_deletes_the_selected_files_and_measures_the_volume():
    volume = _FakeVolume(
        {
            "trajectories/traj_old.json": json.dumps(_trajectory("old", {"timestamp": 0.0})).encode("utf-8"),
            "trajectories/traj_new.json": json.dumps(_trajectory("new", {"timestamp": 10_000_000.0})).encode("utf-8"),
        }
    )
    record = retention.run_retention_cleanup(volume, now=10_000_000.0)

    assert volume.removed == ["trajectories/traj_old.json"]
    assert record["before"]["file_count"] == 2
    assert record["after"]["file_count"] == 1
    assert record["freed_bytes"] == record["deleted_bytes"] > 0
    assert [entry["path"] for entry in record["kept"]] == ["trajectories/traj_new.json"]
    assert record["failures"] == []


def test_the_cleanup_deletes_nothing_when_nothing_is_expired():
    volume = _FakeVolume(
        {"trajectories/traj_new.json": json.dumps(_trajectory("new", {"timestamp": 10_000_000.0})).encode("utf-8")}
    )
    record = retention.run_retention_cleanup(volume, now=10_000_000.0)
    assert volume.removed == []
    assert record["deleted"] == []
    assert record["before"] == record["after"]


def test_the_dry_run_deletes_nothing():
    volume = _FakeVolume(
        {"trajectories/traj_old.json": json.dumps(_trajectory("old", {"timestamp": 0.0})).encode("utf-8")}
    )
    record = retention.run_retention_cleanup(volume, now=10_000_000.0, dry_run=True)
    assert volume.removed == []
    assert record["dry_run"] is True
    assert [entry["path"] for entry in record["deleted"]] == ["trajectories/traj_old.json"]


def test_a_trajectory_that_cannot_be_read_is_kept_and_the_reason_is_recorded():
    """A payload that cannot be read is not skipped: it is measured by its
    modification time, and the reason is recorded."""
    volume = _FakeVolume(
        {"trajectories/traj_broken.json": b"not json"},
        mtimes={"trajectories/traj_broken.json": 10_000_000.0},
    )
    record = retention.run_retention_cleanup(volume, now=10_000_000.0)
    assert volume.removed == []
    assert record["kept"][0]["unreadable_reason"]
    assert record["kept"][0]["timestamp"] is None


def test_an_unreadable_trajectory_of_an_old_modification_time_is_expired():
    """The fallback is the provider's modification time - an unreadable file
    that is old is expired and is deleted."""
    volume = _FakeVolume(
        {"trajectories/traj_broken.json": b"not json"},
        mtimes={"trajectories/traj_broken.json": 0.0},
    )
    record = retention.run_retention_cleanup(volume, now=10_000_000.0)
    assert volume.removed == ["trajectories/traj_broken.json"]
    assert record["trajectories"][0]["unreadable_reason"]


def test_a_failure_of_the_provider_is_recorded_and_does_not_stop_the_cleanup():
    class _FailingVolume(_FakeVolume):
        def remove_file(self, path: str) -> None:
            raise RuntimeError("the provider refused the deletion")

    volume = _FailingVolume(
        {"trajectories/traj_old.json": json.dumps(_trajectory("old", {"timestamp": 0.0})).encode("utf-8")}
    )
    record = retention.run_retention_cleanup(volume, now=10_000_000.0)
    assert record["failures"][0]["path"] == "trajectories/traj_old.json"
    assert record["deleted"] == []


def test_the_measurement_is_the_providers_own_listing():
    volume = _FakeVolume({"trajectories/traj_a.json": b"x" * 42})
    measured = retention.measure(volume)
    assert measured["file_count"] == 1
    assert measured["total_bytes"] == 42
    assert measured["entries"][0]["path"] == "trajectories/traj_a.json"


# --------------------------------------------------------------------------------------
# the procedure starts no container and adds no call site
# --------------------------------------------------------------------------------------


def test_the_cleanup_adds_no_call_site_and_no_declaration():
    """The procedure is a repository-side maintenance step: it changes nothing
    that the signed envelope binds."""
    from core import r1_bounds as r1

    assert "cleanup_trajectories" not in r1.FUNCTION_CLASS
    assert not any("retention" in name for name in r1.FUNCTION_CLASS)
    # The volume and the interval are the ones the deployment and the cost
    # model already use.
    from core.config import config

    assert config.MODEL_VOLUME_NAME == "aegis-model-cache"
    assert config.TRAJECTORY_DIR == "/vol/models/trajectories"
    assert retention.TRAJECTORY_DIR == "trajectories"


def test_the_command_line_of_the_procedure_is_explicit():
    from benchmarks import run_retention_cleanup as procedure

    parser = procedure.build_parser()
    arguments = parser.parse_args(["--run-id", "run-default", "--dry-run"])
    assert arguments.run_id == "run-default"
    assert arguments.dry_run is True
    assert arguments.retention_sec == retention.DEFAULT_RETENTION_SEC
    assert arguments.volume == "aegis-model-cache"
