"""
core/dropbox_bridge.py

Automated communication bridge between Antigravity (execution agent) and
external AI Supervisor via shared Dropbox repository folder.

Handles:
- Bidirectional synchronization between local workspace and Dropbox folder.
- Hash-based change detection for AI_SUPERVISOR_INBOX.md.
- Structured state tracking via BRIDGE_STATE.json.
- Atomic updates to AI_AGENT_OUTBOX.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DropboxBridge")

# Configurable workspace paths for Windows, Linux, and Modal workers.
_DEFAULT_LOCAL_WORKSPACE = Path(__file__).resolve().parent.parent
_DEFAULT_DROPBOX_WORKSPACE = Path(r"D:\\Install\\I\\Dropbox\\Coding\\GitHub\\Agentic-security-RLVR")
LOCAL_WORKSPACE = Path(os.environ.get("AEGIS_LOCAL_WORKSPACE", str(_DEFAULT_LOCAL_WORKSPACE)))
DROPBOX_WORKSPACE = Path(os.environ.get("AEGIS_DROPBOX_WORKSPACE", str(_DEFAULT_DROPBOX_WORKSPACE)))

INBOX_FILENAME = "AI_SUPERVISOR_INBOX.md"
OUTBOX_FILENAME = "AI_AGENT_OUTBOX.md"
STATE_FILENAME = "BRIDGE_STATE.json"
PROTOCOL_FILENAME = "BRIDGE_PROTOCOL.md"

IGNORED_PATTERNS = {
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".gitignore",
    ".github",
    ".DS_Store",
    "*.pyc",
    "*.pyo",
    "*.pyd",
}


def compute_file_hash(filepath: Path) -> str:
    """Computes SHA256 hash of a file's content, normalized to strip trailing whitespace."""
    if not filepath.exists() or not filepath.is_file():
        return ""
    try:
        content = filepath.read_bytes().decode("utf-8", errors="replace").strip()
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    except Exception as exc:
        logger.error(f"Error computing hash for {filepath}: {exc}")
        return ""


def load_bridge_state(state_path: Optional[Path] = None) -> Dict[str, Any]:
    """Loads state JSON or returns default initialization."""
    target_path = state_path or (LOCAL_WORKSPACE / STATE_FILENAME)
    if not target_path.exists():
        # Fallback to Dropbox copy ONLY if using default workspace path
        if state_path is None:
            dropbox_state = DROPBOX_WORKSPACE / STATE_FILENAME
            if dropbox_state.exists():
                try:
                    with open(dropbox_state, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
        return {
            "current_round": 1,
            "status": "WAITING_FOR_SUPERVISOR",
            "last_inbox_hash": "",
            "last_updated_at": datetime.now(timezone.utc).isoformat(),
            "active_modal_profile": "neubeginner",
            "latest_checkpoint": "checkpoint-step-2",
        }

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning(f"Could not load state from {target_path}: {exc}. Using default.")
        return {
            "current_round": 1,
            "status": "WAITING_FOR_SUPERVISOR",
            "last_inbox_hash": "",
            "last_updated_at": datetime.now(timezone.utc).isoformat(),
            "active_modal_profile": "neubeginner",
            "latest_checkpoint": "checkpoint-step-2",
        }


def save_bridge_state(
    state: Dict[str, Any],
    local_path: Optional[Path] = None,
    dropbox_path: Optional[Path] = None,
) -> None:
    """Atomically saves state JSON both locally and in Dropbox."""
    state["last_updated_at"] = datetime.now(timezone.utc).isoformat()
    l_path = local_path or (LOCAL_WORKSPACE / STATE_FILENAME)
    d_path = dropbox_path or (DROPBOX_WORKSPACE / STATE_FILENAME)

    serialized = json.dumps(state, indent=2, ensure_ascii=False)
    try:
        l_path.write_text(serialized, encoding="utf-8")
    except Exception as exc:
        logger.error(f"Failed writing local state to {l_path}: {exc}")

    if d_path.parent.exists():
        try:
            d_path.write_text(serialized, encoding="utf-8")
        except Exception as exc:
            logger.error(f"Failed writing Dropbox state to {d_path}: {exc}")


def should_ignore(path: Path) -> bool:
    """Checks if a path should be ignored during synchronization."""
    parts = set(path.parts)
    for ignored in IGNORED_PATTERNS:
        if ignored in parts or path.name == ignored or path.suffix in [".pyc", ".pyo"]:
            return True
    return False


def sync_files_to_dropbox(
    src_root: Path = LOCAL_WORKSPACE,
    dst_root: Path = DROPBOX_WORKSPACE,
) -> int:
    """Copies all non-ignored project files and directories from local to Dropbox."""
    if not dst_root.exists():
        logger.warning(f"Dropbox destination {dst_root} does not exist.")
        return 0

    copied_count = 0
    for src_file in src_root.rglob("*"):
        if src_file.is_file() and not should_ignore(src_file):
            rel_path = src_file.relative_to(src_root)
            dst_file = dst_root / rel_path

            # Don't overwrite newer AI_SUPERVISOR_INBOX in Dropbox with older local inbox
            if rel_path.name == INBOX_FILENAME and dst_file.exists():
                src_mtime = src_file.stat().st_mtime
                dst_mtime = dst_file.stat().st_mtime
                if dst_mtime > src_mtime:
                    continue

            # Copy if missing or modified
            if not dst_file.exists() or src_file.stat().st_mtime > dst_file.stat().st_mtime:
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(src_file, dst_file)
                    copied_count += 1
                except Exception as exc:
                    logger.debug(f"Failed copying {src_file} -> {dst_file}: {exc}")

    logger.info(f"Synchronized {copied_count} file(s) to Dropbox.")
    return copied_count


def sync_inbox_from_dropbox(
    src_root: Path = DROPBOX_WORKSPACE,
    dst_root: Path = LOCAL_WORKSPACE,
) -> bool:
    """Pulls AI_SUPERVISOR_INBOX.md from Dropbox if it has newer changes."""
    src_inbox = src_root / INBOX_FILENAME
    dst_inbox = dst_root / INBOX_FILENAME

    if not src_inbox.exists():
        return False

    src_hash = compute_file_hash(src_inbox)
    dst_hash = compute_file_hash(dst_inbox)

    if src_hash and src_hash != dst_hash:
        try:
            shutil.copy2(src_inbox, dst_inbox)
            logger.info(f"Updated local inbox from Dropbox (hash: {src_hash[:8]}).")
            return True
        except Exception as exc:
            logger.error(f"Error syncing inbox from Dropbox: {exc}")
            return False
    return False


def check_for_supervisor_task(
    dropbox_root: Path = DROPBOX_WORKSPACE,
    local_root: Path = LOCAL_WORKSPACE,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Checks if the AI Supervisor has posted a new task/message.
    
    Returns:
        (has_new_task, inbox_content, current_state)
    """
    # 1. Sync inbox from Dropbox if needed
    sync_inbox_from_dropbox(src_root=dropbox_root, dst_root=local_root)

    inbox_file = local_root / INBOX_FILENAME
    if not inbox_file.exists():
        return False, "", {}

    inbox_content = inbox_file.read_text(encoding="utf-8", errors="replace")
    current_hash = compute_file_hash(inbox_file)
    state = load_bridge_state(local_root / STATE_FILENAME)

    last_hash = state.get("last_inbox_hash", "")
    current_status = state.get("status", "WAITING_FOR_SUPERVISOR")

    # If hash hasn't changed at all, there are no new modifications
    if not current_hash or current_hash == last_hash:
        return False, inbox_content, state

    # Content has changed. Check whether this is an active task
    # (either explicit tag [STATUS: NEW_TASK] or simply any change made by supervisor)
    has_trigger_status = (
        "[STATUS: NEW_TASK]" in inbox_content
        or "[STATUS: WAITING_FOR_AGENT]" in inbox_content
    )

    # Any new content when waiting for supervisor is treated as a task
    has_new_task = current_status == "WAITING_FOR_SUPERVISOR" or has_trigger_status

    return has_new_task, inbox_content, state


def write_agent_outbox(
    content: str,
    round_num: Optional[int] = None,
    next_status: str = "WAITING_FOR_SUPERVISOR",
    local_root: Path = LOCAL_WORKSPACE,
    dropbox_root: Path = DROPBOX_WORKSPACE,
) -> None:
    """
    Writes output response to AI_AGENT_OUTBOX.md and updates state.
    """
    local_outbox = local_root / OUTBOX_FILENAME
    dropbox_outbox = dropbox_root / OUTBOX_FILENAME

    local_outbox.write_text(content, encoding="utf-8")
    if dropbox_outbox.parent.exists():
        try:
            dropbox_outbox.write_text(content, encoding="utf-8")
        except Exception as exc:
            logger.error(f"Could not write to Dropbox outbox: {exc}")

    # Update state
    state = load_bridge_state(local_root / STATE_FILENAME)
    inbox_hash = compute_file_hash(local_root / INBOX_FILENAME)

    if round_num is not None:
        state["current_round"] = round_num
    state["status"] = next_status
    state["last_inbox_hash"] = inbox_hash

    save_bridge_state(state, local_root / STATE_FILENAME, dropbox_root / STATE_FILENAME)
    # Sync workspace
    sync_files_to_dropbox(src_root=local_root, dst_root=dropbox_root)
    logger.info(f"Agent outbox published (Round {state.get('current_round')}, Status: {next_status}).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Dropbox AI Bridge CLI")
    parser.add_argument("command", choices=["sync", "check", "status", "hash"], help="Command to execute")
    parser.add_argument("--file", type=str, default="", help="Target file for hash calculation")
    args = parser.parse_args()

    if args.command == "sync":
        sync_inbox_from_dropbox()
        sync_files_to_dropbox()
    elif args.command == "check":
        has_task, content, state = check_for_supervisor_task()
        print(f"Has New Task: {has_task}")
        print(f"Current State: {json.dumps(state, indent=2)}")
        if has_task:
            print("--- Inbox Excerpt ---")
            print(content[:500])
    elif args.command == "status":
        state = load_bridge_state()
        print(json.dumps(state, indent=2))
    elif args.command == "hash":
        target = Path(args.file) if args.file else (LOCAL_WORKSPACE / INBOX_FILENAME)
        print(f"File: {target} | Hash: {compute_file_hash(target)}")


if __name__ == "__main__":
    main()
