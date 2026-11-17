"""Verify the pinned revision's cache against the hub's own tree file (read-only)."""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "volume_inventory.json"), encoding="utf-8") as fh:
    report = json.load(fh)

entries = report["entries"]
files = {p: e for p, e in entries.items() if e["type"] == "file"}
links = {p: e for p, e in entries.items() if e["type"] == "symlink"}

print("== huggingface/ breakdown (files) ==")
hf = {p: e for p, e in files.items() if p.startswith("huggingface/")}
buckets = {}
for p, e in hf.items():
    parts = p.split("/")
    if parts[1] == "blobs":
        key = "huggingface/blobs/" + parts[2][:2] + "/…"
    else:
        key = "/".join(parts[:2])
    b = buckets.setdefault(key, {"n": 0, "bytes": 0})
    b["n"] += 1
    b["bytes"] += int(e["size"] or 0)
for k, b in sorted(buckets.items(), key=lambda kv: -kv[1]["bytes"])[:25]:
    print(f"{b['bytes']:>15,} B  n={b['n']:>3}  {k}")

print("\n== symlinks (49) ==")
for p, e in sorted(links.items())[:60]:
    extra = {k: v for k, v in e.items() if k not in ("path", "type", "size", "created_at", "last_modified")}
    print(f"{p}  size={e['size']}  {extra if extra else ''}")

print("\n== all symlink entry keys ==")
sample = next(iter(links.values())) if links else {}
print(json.dumps(sample, indent=2))

print("\n== big blobs (top 20) ==")
for p, e in sorted(hf.items(), key=lambda kv: -int(kv[1]["size"] or 0))[:20]:
    print(f"{int(e['size'] or 0):>15,} B  {p}")
