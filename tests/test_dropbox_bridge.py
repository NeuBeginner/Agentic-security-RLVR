"""
tests/test_dropbox_bridge.py

Unit tests for core/dropbox_bridge.py file-based coordination and state management.
"""

import json
import pytest
from pathlib import Path
from core.dropbox_bridge import (
    compute_file_hash,
    load_bridge_state,
    save_bridge_state,
    sync_files_to_dropbox,
    sync_inbox_from_dropbox,
    check_for_supervisor_task,
    write_agent_outbox,
    INBOX_FILENAME,
    OUTBOX_FILENAME,
    STATE_FILENAME,
)


@pytest.fixture
def temp_bridge_env(tmp_path):
    local_dir = tmp_path / "local"
    dropbox_dir = tmp_path / "dropbox"
    local_dir.mkdir()
    dropbox_dir.mkdir()

    return local_dir, dropbox_dir


def test_compute_file_hash(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello world\n", encoding="utf-8")
    h1 = compute_file_hash(f)
    assert len(h1) == 64

    # Stripped whitespace gives same hash
    f.write_text("hello world   \n\n", encoding="utf-8")
    h2 = compute_file_hash(f)
    assert h1 == h2

    # Different text gives different hash
    f.write_text("different text", encoding="utf-8")
    h3 = compute_file_hash(f)
    assert h1 != h3


def test_state_load_and_save(temp_bridge_env):
    local_dir, dropbox_dir = temp_bridge_env
    state_file = local_dir / STATE_FILENAME
    dropbox_state = dropbox_dir / STATE_FILENAME

    state = load_bridge_state(state_file)
    assert state["status"] == "WAITING_FOR_SUPERVISOR"
    assert state["current_round"] == 1

    state["current_round"] = 2
    state["status"] = "IN_PROGRESS"
    save_bridge_state(state, local_path=state_file, dropbox_path=dropbox_state)

    loaded = load_bridge_state(state_file)
    assert loaded["current_round"] == 2
    assert loaded["status"] == "IN_PROGRESS"

    # Verify written to dropbox too
    assert dropbox_state.exists()
    loaded_dbx = json.loads(dropbox_state.read_text(encoding="utf-8"))
    assert loaded_dbx["current_round"] == 2


def test_sync_inbox_and_task_detection(temp_bridge_env):
    local_dir, dropbox_dir = temp_bridge_env

    # 1. Initially no inbox
    has_task, content, state = check_for_supervisor_task(
        dropbox_root=dropbox_dir, local_root=local_dir
    )
    assert not has_task

    # 2. Supervisor writes to Dropbox inbox
    dbx_inbox = dropbox_dir / INBOX_FILENAME
    dbx_inbox.write_text(
        "### Task from Supervisor\n[STATUS: NEW_TASK]\nPlease train for 3 epochs.",
        encoding="utf-8",
    )

    has_task, content, state = check_for_supervisor_task(
        dropbox_root=dropbox_dir, local_root=local_dir
    )
    assert has_task
    assert "Please train for 3 epochs" in content
    assert (local_dir / INBOX_FILENAME).exists()


def test_write_agent_outbox_and_sync(temp_bridge_env):
    local_dir, dropbox_dir = temp_bridge_env

    # Initialize local inbox
    (local_dir / INBOX_FILENAME).write_text("Task", encoding="utf-8")

    outbox_text = "# Antigravity Report\nEvaluation completed successfully."
    write_agent_outbox(
        content=outbox_text,
        round_num=2,
        next_status="WAITING_FOR_SUPERVISOR",
        local_root=local_dir,
        dropbox_root=dropbox_dir,
    )

    # Check local outbox and state
    assert (local_dir / OUTBOX_FILENAME).read_text(encoding="utf-8") == outbox_text
    state = load_bridge_state(local_dir / STATE_FILENAME)
    assert state["current_round"] == 2
    assert state["status"] == "WAITING_FOR_SUPERVISOR"

    # Check Dropbox synced
    assert (dropbox_dir / OUTBOX_FILENAME).exists()
    assert (dropbox_dir / OUTBOX_FILENAME).read_text(encoding="utf-8") == outbox_text
