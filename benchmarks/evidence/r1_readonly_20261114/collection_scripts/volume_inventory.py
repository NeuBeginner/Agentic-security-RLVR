"""Authoritative read-only inventory of the Modal Volume 'aegis-model-cache'.

Two independent listings are compared:
  A) one recursive listing from the root  (Volume.iterdir("", recursive=True))
  B) a breadth-first walk with recursive=False per directory

Only the intersection (== A == B) is accepted, so a truncated or duplicated
listing cannot inflate the byte total.  Nothing is written, committed or removed.
"""

import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

import modal

VOLUME_NAME = "aegis-model-cache"
ENVIRONMENT = "main"
PINNED_REPO_DIR = "huggingface/models--qtum--Qwen3-Coder-30B-A3B-Audit"
PINNED_REVISION = "655425b794ae4a19f2ea16fa480c6b39102721ee"
MANIFEST_PATH = "model_cache_manifest.json"
TREES_PATH = f"{PINNED_REPO_DIR}/trees/{PINNED_REVISION}.json"

HERE = os.path.dirname(os.path.abspath(__file__))


def entry_dict(e):
    return {
        "path": e.path,
        "type": str(e.type).rsplit(".", 1)[-1].lower(),
        "size": getattr(e, "size", None),
        "created_at": getattr(e, "created_at", None),
        "last_modified": getattr(e, "last_modified", None),
    }


def listing_a(vol):
    """One recursive listing from the root."""
    return {e.path: entry_dict(e) for e in vol.iterdir("", recursive=True)}


def listing_b(vol):
    """Breadth-first walk with one level per call (recursive=False)."""
    out = {}
    queue = [""]
    seen_dirs = set()
    while queue:
        current = queue.pop(0)
        if current in seen_dirs:
            continue
        seen_dirs.add(current)
        for e in vol.iterdir(current, recursive=False):
            out[e.path] = entry_dict(e)
            if str(e.type).endswith("DIRECTORY"):
                queue.append(e.path)
    return out


def read_all(vol, path):
    """Read a file's bytes (read-only) from a Modal Volume, SDK-version agnostic."""
    import asyncio

    res = vol.read_file(path)
    if isinstance(res, (bytes, bytearray)):
        return bytes(res)
    if hasattr(res, "__aiter__"):
        async def _collect():
            chunks = []
            async for chunk in res:
                chunks.append(chunk)
            return b"".join(chunks)

        return asyncio.run(_collect())
    if hasattr(res, "__await__"):
        return asyncio.run(res)
    if hasattr(res, "__iter__"):
        return b"".join(
            chunk if isinstance(chunk, (bytes, bytearray)) else bytes(chunk)
            for chunk in res
        )
    raise TypeError(f"unsupported read_file result: {type(res)}")


def iso(ts):
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return str(ts)


def main():
    started = time.time()
    vol = modal.Volume.from_name(VOLUME_NAME, environment_name=ENVIRONMENT)

    a = listing_a(vol)
    b = listing_b(vol)
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    identical = set(a) == set(b)

    # accept the listing only if both methods agree
    entries = a if identical else b
    agreement = "IDENTICAL" if identical else "MISMATCH"

    files = {p: e for p, e in entries.items() if e["type"] == "file"}
    dirs = {p: e for p, e in entries.items() if e["type"] == "directory"}
    links = {p: e for p, e in entries.items() if e["type"] == "symlink"}
    other = {
        p: e for p, e in entries.items() if e["type"] not in ("file", "directory", "symlink")
    }

    file_bytes = sum(int(e["size"] or 0) for e in files.values())
    link_bytes = sum(int(e["size"] or 0) for e in links.values())

    groups = defaultdict(lambda: {"files": 0, "bytes": 0})
    for p, e in files.items():
        top = p.split("/")[0] or "/"
        groups[top]["files"] += 1
        groups[top]["bytes"] += int(e["size"] or 0)

    pinned = {p: e for p, e in files.items() if p.startswith(PINNED_REPO_DIR)}
    pinned_bytes = sum(int(e["size"] or 0) for e in pinned.values())

    staging = {
        p: e
        for p, e in entries.items()
        if any(m in p for m in (".incomplete", ".tmp", ".partial", ".staging"))
    }

    # ---- the manifest R2p would have written (must NOT exist yet) --------------
    manifest = {"path": MANIFEST_PATH, "present": MANIFEST_PATH in entries}
    if manifest["present"]:
        raw = read_all(vol, MANIFEST_PATH)
        manifest["size_bytes"] = len(raw)
        manifest["sha256"] = hashlib.sha256(raw).hexdigest()
        manifest["content"] = json.loads(raw.decode("utf-8"))

    # ---- the hub cache's own tree file for the pinned revision ----------------
    trees = {
        "path": TREES_PATH,
        "present": TREES_PATH in entries,
        "size_bytes": entries.get(TREES_PATH, {}).get("size"),
    }
    tree_files = []
    if trees["present"]:
        raw = read_all(vol, TREES_PATH)
        trees["sha256"] = hashlib.sha256(raw).hexdigest()
        parsed = json.loads(raw.decode("utf-8"))
        trees["top_level_keys"] = sorted(parsed.keys()) if isinstance(parsed, dict) else None
        tree_files = parsed if isinstance(parsed, list) else parsed.get("files", [])
        trees["tree_entries"] = len(tree_files)

    report = {
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "collector": "modal SDK 1.5.5 Volume.iterdir (read-only; no write/commit/remove)",
        "volume_name": VOLUME_NAME,
        "environment": ENVIRONMENT,
        "modal_profile": "neubeginner",
        "modal_client_version": modal.__version__,
        "listing_agreement": agreement,
        "listing_a_entries": len(a),
        "listing_b_entries": len(b),
        "only_in_a": only_a[:50],
        "only_in_b": only_b[:50],
        "pinned_repo_dir": PINNED_REPO_DIR,
        "pinned_revision": PINNED_REVISION,
        "totals": {
            "entries": len(entries),
            "files": len(files),
            "dirs": len(dirs),
            "symlinks": len(links),
            "other_types": len(other),
            "file_bytes": file_bytes,
            "file_gib": round(file_bytes / (1024 ** 3), 6),
            "symlink_bytes_as_reported": link_bytes,
            "pinned_repo_files": len(pinned),
            "pinned_repo_bytes": pinned_bytes,
            "pinned_repo_gib": round(pinned_bytes / (1024 ** 3), 6),
        },
        "groups": {
            name: {
                "files": g["files"],
                "bytes": g["bytes"],
                "gib": round(g["bytes"] / (1024 ** 3), 6),
            }
            for name, g in sorted(groups.items())
        },
        "staging_leftovers": staging,
        "manifest": manifest,
        "trees": trees,
        "entries": entries,
        "elapsed_sec": round(time.time() - started, 3),
    }

    out = os.path.join(HERE, "volume_inventory.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    summary = {k: v for k, v in report.items() if k not in ("entries", "staging_leftovers")}
    summary["staging_leftover_count"] = len(staging)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    sys.exit(main())
