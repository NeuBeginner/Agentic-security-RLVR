"""Analyse the read-only volume inventory: per-subtree bytes, largest files, manifest."""

import hashlib
import json
import os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "volume_inventory.json"), encoding="utf-8") as fh:
    report = json.load(fh)

entries = report["entries"]
files = [e for e in entries if e.get("type") == "file"]

# ---- level-2 groups ---------------------------------------------------------
groups = defaultdict(lambda: {"files": 0, "bytes": 0})
for e in files:
    parts = (e["path"] or "").split("/")
    key = "/".join(parts[:2]) if len(parts) > 1 else (parts[0] or "/")
    groups[key]["files"] += 1
    groups[key]["bytes"] += int(e.get("size") or 0)

print("== level-2 groups ==")
for name, g in sorted(groups.items(), key=lambda kv: -kv[1]["bytes"]):
    print(f"{g['bytes']:>15,} B  {g['files']:>5} files  {g['bytes']/1024**3:>10.3f} GiB  {name}")

print("\n== level-3 groups under huggingface ==")
g3 = defaultdict(lambda: {"files": 0, "bytes": 0})
for e in files:
    parts = (e["path"] or "").split("/")
    if parts[0] != "huggingface":
        continue
    key = "/".join(parts[:3])
    g3[key]["files"] += 1
    g3[key]["bytes"] += int(e.get("size") or 0)
for name, g in sorted(g3.items(), key=lambda kv: -kv[1]["bytes"])[:20]:
    print(f"{g['bytes']:>15,} B  {g['files']:>5} files  {name}")

print("\n== 25 largest files ==")
for e in sorted(files, key=lambda e: -int(e.get("size") or 0))[:25]:
    print(f"{int(e.get('size') or 0):>15,} B  {e['path']}")

print("\n== manifest ==")
print(json.dumps(report["manifest"], indent=2)[:2000])

print("\n== pinned repo dir: file list (path, size) ==")
pinned = [
    e for e in files
    if (e["path"] or "").startswith("huggingface/models--qtum--Qwen3-Coder-30B-A3B-Audit")
]
for e in sorted(pinned, key=lambda e: -int(e.get("size") or 0))[:40]:
    print(f"{int(e.get('size') or 0):>14,} B  {e['path']}")
print(f"pinned files={len(pinned)} bytes={sum(int(e.get('size') or 0) for e in pinned):,}")

print("\n== snapshots of pinned repo ==")
for e in entries:
    p = e.get("path") or ""
    if p.startswith("huggingface/models--qtum--Qwen3-Coder-30B-A3B-Audit/snapshots"):
        print(f"  {e.get('type')}  {p}  {e.get('size')}")

print("\n== staging leftovers (dedup) ==")
seen = set()
for e in report["staging_leftovers"]:
    p = e.get("path")
    if p in seen:
        continue
    seen.add(p)
print(f"unique staging paths: {len(seen)}")
for p in sorted(seen):
    if p.endswith(".lock"):
        continue
    print(f"  {p}")
print(f"  (+ {sum(1 for p in seen if p.endswith('.lock'))} *.lock files)")
