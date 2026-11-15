"""The preparation of the evidence regeneration of Iterations 14-23.

Three things, none of them a run:

* ``inventory`` - the deterministic inventory of the fabricated ``modal-app://``
  URIs of the published artifacts tree: every occurrence with its file and its
  JSON path, and the **field map** that says what each of them becomes in a
  new run;
* ``plan`` - the exact command of the new run directory and of its
  validation, printed - never executed; and
* ``verify`` - the proof that the published run directory is untouched: the
  digests of its files are the digests of the historical record.

The script performs no provider call, no deployment, no volume operation, no
model download and no paid computation. It never writes into the published
run directory: the directory is read, and the field map is written next to
the other evidence files.

**The new run is the owner's decision.** The script prepares it and stops
before it: the command of ``plan`` is a proposal, not an action.

Usage::

    python -m benchmarks.prepare_evidence_regeneration inventory
    python -m benchmarks.prepare_evidence_regeneration plan
    python -m benchmarks.prepare_evidence_regeneration verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

#: The published run directory. It is the **historical** record: the digests
#: of its files are pinned by the published evidence and are never rewritten.
PUBLISHED_RUN_DIR = "benchmarks/artifacts/run_1794209615_70f5d22"

#: The root-level summary of the published run. It carries the same
#: fabricated URIs as the run directory and is published separately.
PUBLISHED_LATEST_SUMMARY = "benchmarks/artifacts/latest_summary.json"

#: The prefix of a fabricated Modal URI.
SYNTHETIC_URI_PREFIX = "modal-app://"

#: The field map of the regeneration.
FIELD_MAP_PATH = "benchmarks/evidence/evidence_regeneration_field_map.json"

#: The contract that replaces a fabricated URI in a new run.
REPLACEMENT_CONTRACT = (
    "the new run records the reference as the provider-issued value, or as an "
    "explicit NOT_AVAILABLE fact with a reason and a verified evidence reference - "
    "never as a fabricated URI"
)

#: The code that refuses a fabricated URI.
REFUSED_BY = (
    "benchmarks/evidence_integrity.py::validate_modal_invocation_provenance (the "
    "legacy log-URI fields of a stage) and benchmarks/protocol.py::"
    "reject_synthetic_modal_uris (every field of the artifact)"
)


def _git(*args: str) -> Optional[str]:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=_ROOT, capture_output=True, text=True, timeout=60
        )
    except Exception:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _tracked_json_files() -> List[str]:
    """The tracked JSON files of the published artifacts tree - deterministically.

    The inventory reads the **git blobs**, not the working tree: the working
    tree of a Windows checkout holds CRLF, the blobs hold LF, and the
    inventory has to be the same on every machine.
    """
    listing = _git("ls-files", "benchmarks/artifacts")
    if listing is None:
        return []
    return sorted(
        path for path in listing.splitlines() if path.endswith(".json")
    )


def _occurrences(node: Any, prefix: str = "") -> List[Tuple[str, str]]:
    """Every fabricated URI of a JSON document with its JSON path."""
    found: List[Tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.extend(_occurrences(value, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_occurrences(value, f"{prefix}[{index}]"))
    elif isinstance(node, str) and node.startswith(SYNTHETIC_URI_PREFIX):
        found.append((prefix, node))
    return found


def _blob_bytes(relative_path: str) -> bytes:
    """The bytes of a tracked file as the git object holds them."""
    completed = subprocess.run(
        ["git", "cat-file", "blob", f"HEAD:{relative_path}"],
        cwd=_ROOT,
        capture_output=True,
        timeout=60,
    )
    if completed.returncode != 0:
        return b""
    return completed.stdout


def build_inventory() -> Dict[str, Any]:
    """The inventory of every fabricated URI of the published artifacts tree."""
    per_file: List[Dict[str, Any]] = []
    occurrences: List[Dict[str, Any]] = []
    for relative_path in _tracked_json_files():
        raw = _blob_bytes(relative_path)
        if not raw:
            continue
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        found = _occurrences(document)
        if not found:
            continue
        per_file.append(
            {
                "file": relative_path,
                "occurrences": len(found),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "byte_length": len(raw),
            }
        )
        for json_path, value in found:
            stage = ""
            field = ""
            if ".stages." in json_path:
                tail = json_path.split(".stages.", 1)[1]
                stage = tail.split(".", 1)[0]
                field = tail.split(".", 1)[1] if "." in tail else tail
            occurrences.append(
                {
                    "file": relative_path,
                    "json_path": json_path,
                    "stage": stage,
                    "field": field,
                    "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    "value_length": len(value),
                }
            )
    return {
        "schema": "aegis-rlvr/evidence-regeneration-field-map/1",
        "published_run_dir": PUBLISHED_RUN_DIR,
        "synthetic_uri_prefix": SYNTHETIC_URI_PREFIX,
        "total_occurrences": sum(row["occurrences"] for row in per_file),
        "files_with_occurrences": len(per_file),
        "files": per_file,
        "occurrences": occurrences,
    }


def build_field_map(inventory: Dict[str, Any]) -> Dict[str, Any]:
    """The field map: what every fabricated URI becomes in a new run."""
    return {
        "schema": "aegis-rlvr/evidence-regeneration-field-map/1",
        "purpose": (
            "the mapping of the 165 fabricated Modal URIs of the published artifacts "
            "tree onto the contract of a new run - the historical record keeps its "
            "bytes and its digests"
        ),
        "status": "PREPARED - the new run is not authorised and not performed",
        "published_run_dir": PUBLISHED_RUN_DIR,
        "published_run_dir_is_immutable": True,
        "synthetic_uri_prefix": SYNTHETIC_URI_PREFIX,
        "refused_by": REFUSED_BY,
        "replacement_contract": REPLACEMENT_CONTRACT,
        "total_occurrences": inventory["total_occurrences"],
        "files": inventory["files"],
        "field_map": [
            {
                **occurrence,
                "replacement": REPLACEMENT_CONTRACT,
                "refused_by": REFUSED_BY,
            }
            for occurrence in inventory["occurrences"]
        ],
    }


def write_field_map(path: Path, field_map: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(field_map, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    path.write_bytes(payload)
    return path


def plan_run() -> Dict[str, Any]:
    """The command of the new run - printed, never executed."""
    commit_sha = _git("rev-parse", "HEAD") or ""
    short = commit_sha[:7]
    return {
        "status": "PREPARED - NOT AUTHORISED, NOT EXECUTED",
        "why": (
            "the new run needs the provider, the model and the money of the cycle; "
            "the owner authorises it"
        ),
        "commit_sha": commit_sha,
        "run_id": f"run_<epoch>_{short}",
        "run_directory": f"benchmarks/artifacts/run_<epoch>_{short}/",
        "run_id_rule": (
            "the directory suffix is the commit SHA of the run: the manifest's "
            "git.commit_sha[:7] has to equal it (benchmarks/protocol.py)"
        ),
        "steps": [
            "1. the checkout of the commit that runs, clean, with its full history",
            "2. python -m benchmarks.benchmark_runner --mode real "
            "--artifacts-dir benchmarks/artifacts",
            "3. the new iteration validator of the owner, bound to the new run "
            "directory (--run-dir), never to the published one",
            "4. the closure validator, with the new row of the historical evidence",
            "5. the field map of this regeneration is applied to the new run",
        ],
        "never": [
            "the published run directory is not modified, renamed or rewritten",
            "the published digests stay the digests of the historical record",
            "the historical Iterations 14-18 stay FAILED (0/16 targets)",
            "the authoritative run is selected explicitly, never by recency",
        ],
    }


def verify_published_run() -> Dict[str, Any]:
    """The proof that the published run directory is untouched."""
    changed = _git("diff", "--name-only", "HEAD", "--", PUBLISHED_RUN_DIR)
    status = _git("status", "--porcelain", "--", PUBLISHED_RUN_DIR) or ""
    return {
        "published_run_dir": PUBLISHED_RUN_DIR,
        "committed_changes": changed or "",
        "working_tree_changes": status,
        "untouched": not changed and not status,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    inventory_parser = sub.add_parser("inventory", help="the inventory and the field map")
    inventory_parser.add_argument(
        "--write", action="store_true", help="write the field map into the evidence tree"
    )
    inventory_parser.add_argument("--output", default=FIELD_MAP_PATH)

    sub.add_parser("plan", help="the command of the new run - printed, never executed")
    sub.add_parser("verify", help="the proof that the published run directory is untouched")

    args = parser.parse_args(argv)

    if args.command == "inventory":
        inventory = build_inventory()
        print(
            "inventoried {files} files with {total} fabricated URIs".format(
                files=inventory["files_with_occurrences"],
                total=inventory["total_occurrences"],
            )
        )
        for row in inventory["files"]:
            print(f"  {row['occurrences']:>3}  {row['file']}")
        field_map = build_field_map(inventory)
        if args.write:
            written = write_field_map(_ROOT / args.output, field_map)
            print(f"wrote {written.relative_to(_ROOT).as_posix()}")
        else:
            print("(dry run - use --write to write the field map)")
        return 0

    if args.command == "plan":
        plan = plan_run()
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        return 0

    if args.command == "verify":
        report = verify_published_run()
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["untouched"] else 1

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
