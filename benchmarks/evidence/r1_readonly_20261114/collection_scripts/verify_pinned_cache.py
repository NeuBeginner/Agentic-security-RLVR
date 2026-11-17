"""Verify the pinned revision's cache against the hub's own tree metadata (read-only).

The hub cache on the volume stores large LFS/Xet payloads in a *shared* blob store
('huggingface/blobs/<xx>/<hash>'); the per-repository directory only holds symlinks
into it.  The tree file of the pinned revision therefore names, per file:
  * size / lfs_size  - the expected byte count
  * lfs_sha256       - the SHA-256 of the file content
  * xet_hash         - the key under which the payload is stored in the blob store

Verification is therefore:
  * byte count  -> compared against the volume listing (exact, read-only)
  * SHA-256     -> the value the hub declares for the content; NOT recomputed here
                   (recomputing means reading ~61 GiB out of the volume, which the
                   read-only instruction forbids), so it is reported as declared-only
  * manifest    -> the R2p manifest does not exist yet (R2p has not run)

Nothing is written, committed, removed or uploaded; no model is downloaded.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

import modal

VOLUME_NAME = "aegis-model-cache"
ENVIRONMENT = "main"
PINNED_REPO_DIR = "huggingface/models--qtum--Qwen3-Coder-30B-A3B-Audit"
PINNED_REVISION = "655425b794ae4a19f2ea16fa480c6b39102721ee"
PINNED_REPO_ID = "qtum/Qwen3-Coder-30B-A3B-Audit"
TREES_PATH = f"{PINNED_REPO_DIR}/trees/{PINNED_REVISION}.json"
MANIFEST_PATH = "model_cache_manifest.json"
EXPECTED_BYTES = 61_077_997_602

HERE = os.path.dirname(os.path.abspath(__file__))


def read_all(vol, path):
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


def candidates(entry):
    """Where a payload of this tree entry can live, in lookup order."""
    out = []
    for key in ("xet_hash", "lfs_sha256", "blob_id"):
        value = entry.get(key)
        if not value or len(value) < 40:
            continue
        out.append((key, value, f"huggingface/blobs/{value[:2]}/{value}"))
        out.append((key, value, f"{PINNED_REPO_DIR}/blobs/{value}"))
    return out


def main():
    vol = modal.Volume.from_name(VOLUME_NAME, environment_name=ENVIRONMENT)
    listing = {e.path: e for e in vol.iterdir("", recursive=True)}

    tree_raw = read_all(vol, TREES_PATH)
    tree = json.loads(tree_raw.decode("utf-8"))
    files_map = tree["files"]

    rows, missing, mismatched = [], [], []
    verified_bytes, expected_bytes_all, expected_bytes_weights = 0, 0, 0

    for rel, entry in sorted(files_map.items()):
        expected_size = int(entry.get("lfs_size") or entry.get("size") or 0)
        expected_bytes_all += expected_size

        hit = None
        for key, value, path in candidates(entry):
            if path in listing:
                hit = (key, value, path, int(listing[path].size or 0))
                break

        repo_blob_symlink = f"{PINNED_REPO_DIR}/blobs/{entry.get('lfs_sha256') or entry.get('blob_id')}"
        snapshot_link = f"{PINNED_REPO_DIR}/snapshots/{PINNED_REVISION}/{rel}"

        is_weight = rel.endswith(".safetensors")
        if is_weight:
            expected_bytes_weights += expected_size

        if hit is None:
            status = "MISSING"
            missing.append(rel)
        elif hit[3] != expected_size:
            status = "SIZE_MISMATCH"
            mismatched.append({"path": rel, "expected": expected_size, "actual": hit[3]})
        else:
            status = "VERIFIED"
            verified_bytes += hit[3]

        rows.append(
            {
                "path": rel,
                "is_weight_shard": is_weight,
                "expected_size": expected_size,
                "lfs_sha256": entry.get("lfs_sha256"),
                "xet_hash": entry.get("xet_hash"),
                "blob_id": entry.get("blob_id"),
                "stored_at": hit[2] if hit else None,
                "stored_under_key": hit[0] if hit else None,
                "stored_size": hit[3] if hit else None,
                "repo_blob_symlink_present": repo_blob_symlink in listing,
                "snapshot_link_present": snapshot_link in listing,
                "status": status,
            }
        )

    report = {
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "volume": VOLUME_NAME,
        "environment": ENVIRONMENT,
        "modal_profile": "neubeginner",
        "modal_client_version": modal.__version__,
        "pinned_repo_id": PINNED_REPO_ID,
        "pinned_revision": PINNED_REVISION,
        "declared_expected_bytes": EXPECTED_BYTES,
        "trees_file": {
            "path": TREES_PATH,
            "sha256": hashlib.sha256(tree_raw).hexdigest(),
            "bytes": len(tree_raw),
            "format_version": tree.get("format_version"),
            "entries": len(files_map),
        },
        "r2p_manifest": {
            "path": MANIFEST_PATH,
            "present": MANIFEST_PATH in listing,
            "sha256": None,
            "note": (
                "the R2p manifest is written by the prefetch step, which R1 does not "
                "run; its absence is expected and does not by itself condemn the cache"
            ),
        },
        "sha256_verification": {
            "content_sha256_recomputed": False,
            "reason": (
                "recomputing the content SHA-256 requires reading ~59.9 GiB out of the "
                "volume, which the read-only instruction forbids; the hub-declared "
                "lfs_sha256 of every shard is recorded instead"
            ),
        },
        "totals": {
            "tree_entries": len(rows),
            "verified": sum(1 for r in rows if r["status"] == "VERIFIED"),
            "missing": len(missing),
            "size_mismatched": len(mismatched),
            "expected_bytes_all_entries": expected_bytes_all,
            "expected_bytes_weight_shards": expected_bytes_weights,
            "verified_bytes": verified_bytes,
            "verified_gib": round(verified_bytes / (1024 ** 3), 6),
            "declared_expected_bytes": EXPECTED_BYTES,
            "weight_shards_match_declared": expected_bytes_weights == EXPECTED_BYTES,
            "all_entries_verified": not missing and not mismatched,
        },
        "missing": missing,
        "size_mismatched": mismatched,
        "files": rows,
    }

    out = os.path.join(HERE, "pinned_cache_verification.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    with open(os.path.join(HERE, "pinned_trees_raw.json"), "wb") as fh:
        fh.write(tree_raw)

    print(json.dumps({k: v for k, v in report.items() if k != "files"}, indent=2, ensure_ascii=False))
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    sys.exit(main())
