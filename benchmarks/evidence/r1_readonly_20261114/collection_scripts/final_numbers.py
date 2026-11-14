"""Final numbers for the read-only evidence report."""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "volume_inventory.json"), encoding="utf-8") as fh:
    inv = json.load(fh)
with open(os.path.join(HERE, "pinned_cache_verification.json"), encoding="utf-8") as fh:
    pin = json.load(fh)

entries = inv["entries"]
files = {p: e for p, e in entries.items() if e["type"] == "file"}
links = {p: e for p, e in entries.items() if e["type"] == "symlink"}

lock_files = {p: e for p, e in files.items() if p.endswith(".lock")}
refs_files = {p: e for p, e in files.items() if p.endswith(".refs")}
locks_dir = {p: e for p, e in files.items() if "/.locks/" in p}
hidden = {p: e for p, e in files.items() if "/." in p.split("/")[-1]}
incomplete = {
    p: e for p, e in files.items()
    if any(m in p for m in (".incomplete", ".tmp", ".partial", ".staging", ".pending"))
}

print("== leftovers ==")
print("hub .lock files (0 bytes):", len(lock_files), "bytes:", sum(int(e['size'] or 0) for e in lock_files.values()))
print("hub .refs files:", len(refs_files), "bytes:", sum(int(e['size'] or 0) for e in refs_files.values()))
print("under huggingface/.locks/:", len(locks_dir))
print("hidden-name files:", len(hidden), list(hidden)[:6])
print("true staging leftovers (.incomplete/.tmp/.partial/.staging/.pending):", len(incomplete), list(incomplete)[:10])
print("symlinks:", len(links))

print("\n== top-level groups ==")
for name, g in inv["groups"].items():
    print(f"{name}: {g['files']} files, {g['bytes']:,} B, {g['gib']} GiB")

print("\n== checkpoints ==")
ck = {p: e for p, e in files.items() if p.startswith("checkpoints/")}
for p, e in sorted(ck.items()):
    print(f"{int(e['size'] or 0):>14,} B  {p}")

print("\n== pinned cache ==")
t = pin["totals"]
print(json.dumps(t, indent=2))
print("missing:", pin["missing"])
for row in pin["files"]:
    if row["status"] != "VERIFIED" or row["is_weight_shard"]:
        print(
            f"  {row['status']:<14} {str(row['expected_size']):>12}  "
            f"{row['stored_size'] if row['stored_size'] is not None else '-':>12}  {row['path']}"
        )
