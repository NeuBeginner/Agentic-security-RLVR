# Evidence Regeneration — Architecture & Plan

**Status:** proposal for independent review. **Planning only — nothing was implemented, no published evidence was touched, no Modal/GPU/paid execution occurred.**

| | |
|---|---|
| Baseline commit | `a8a88575aed08c852b65e0fd3972846b9cf791dc` |
| Baseline branch | `integration/reconcile-upstream-7876f6e-into-iteration-14` (PR #13 head) |
| Planning branch | `docs/evidence-regeneration-architecture-plan` (based on the baseline commit, no other parent) |
| Upstream reference | `origin/feat/empirical-benchmark-runner` @ `7876f6e` |
| Date | 2026-11-11 |
| Scope | Iteration 14–23 evidence set, `benchmarks/evidence/`, `benchmarks/artifacts/` |

---

## 0. Summary of findings

This plan answers the task in
[issuecomment-6790610650](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/13#issuecomment-6790610650).
Five findings changed the shape of the plan; they are stated first because they invalidate
two premises of the task.

| # | Finding | Consequence for the plan |
|---|---|---|
| **F1** | The pseudo-URI inventory is **165**, not 99 — and not 132. The 99 of the task counts only two of the four files that carry the URIs; a script that scans a single run directory counts 132 and misses the root-level `latest_summary.json` (§2). | The inventory in §2 enumerates all 165 occurrences, by file, JSON path and value, over the **whole** tracked artifacts tree. |
| **F2** | The current validator **already rejects** the published pseudo-URIs — but for a *different, earlier* reason than the URI. Iterations 14–18 fail on `missing 'function_call_id'` and `missing 'image_digest'`, i.e. the URI check is never reached (§4.2). | The regeneration cannot be "clean up the URI"; it must **replace the whole provenance schema** of the artifacts, because the schema the URI lives in is itself rejected. |
| **F3** | The upstream bytes are **not** a drop-in replacement. Upstream's rewritten artifacts still fail the iteration-line validators, and they introduce a *new* defect: a synthetic `container_id` of the exact shape the validator forbids (§3.2). | The upstream bytes cannot be taken as-is. §5 specifies a third contract: iteration-line schema **+** upstream's `NOT_AVAILABLE` honesty **+** upstream's field rename, with the upstream defects fixed. |
| **F4** | `has_synthetic_modal_uri` is **not enforced** on the authoritative paths. In Iterations 14–16 it is recorded as a diagnostic field (`synthetic_uri_present`) next to a billing check whose verdict it does not influence; Iterations 17–23 and the closure validator do not call it at all (§4.3). | §6 specifies the exact call-path changes needed to make the detector authoritative, plus the negative tests that prove it. |
| **F5** | The SHA-256 pins **do** bind the 16 target artifacts. `reproducibility_manifest.json → adapters.baseline_5.artifact_files` carries 48 `(relative_path, size_bytes, sha256)` records — 16 target JSONs + 32 stdout/stderr files — and all 16 JSON digests match the git blob bytes (§7.2). | The blast radius of a regeneration is **wider** than the task assumes: regenerating the target artifacts forces a re-pin of the manifest, and the manifest and the harness validation already disagree on 15 of the 32 stdout digests because they were computed over different line-ending conventions (§7.3). |

The central architectural conclusion: **the regeneration is a schema migration, not a value
cleanup.** The pseudo-URI is a symptom; the disease is that the published artifacts carry a
provenance schema that the current validator refuses to accept in any form.

---

## 1. Baseline, verification method, and what "published" means

### 1.1 Baseline and clean-worktree status

```
$ git -C <repo> rev-parse HEAD
a8a88575aed08c852b65e0fd3972846b9cf791dc

$ git -C <repo> status --porcelain=v1
(empty)
```

The working tree was clean before the planning branch was created and no tracked file was
modified while producing this document. The planning branch has exactly one parent —
`a8a88575aed08c852b65e0fd3972846b9cf791dc` — so it contains no upstream commits and no
merge.

### 1.2 Which files are "published evidence"

`benchmarks/artifacts/` is listed in `.gitignore` (line 14), but **159** files of that tree
are **tracked** and therefore published:

```
$ git ls-files benchmarks/artifacts | wc -l
159
```

The tree is **not** one run. It holds four run directories and one root-level summary:

| Tracked path | Files | Role |
|---|---|---|
| `benchmarks/artifacts/run_1794152785_e4e94fc/` | 4 | earlier, partial run (2 targets + manifest + summary) |
| `benchmarks/artifacts/run_1794157194_864133b/` | 50 | earlier, complete run |
| `benchmarks/artifacts/run_1794174995_39eb396/` | 50 | earlier, complete run |
| `benchmarks/artifacts/run_1794209615_70f5d22/` | 54 | **the published run of this plan** |
| `benchmarks/artifacts/latest_summary.json` | 1 | root-level mirror of the published run's `summary.json` |

The published run is `run_1794209615_70f5d22` — the one the iteration-line validators read by
default (`DEFAULT_RUN_DIR` in `benchmarks/validate_iteration14_evidence.py:66`) and the one
whose `summary.json` is mirrored by the root-level `latest_summary.json`. It contains
**54** tracked files:

```
$ git ls-files benchmarks/artifacts/run_1794209615_70f5d22/ | wc -l
54
```

— 18 JSON (16 target artifacts + `reproducibility_manifest.json` + `summary.json`) and 36 text
files (16 × `_stdout.txt`, 16 × `_stderr.txt`, 4 × `_replay_stdout.txt` / `_replay_stderr.txt`).

The three older run directories are earlier runs. They carry **no** `modal-app://` occurrence
(§2.2), so they are outside the pseudo-URI scope — but they are published bytes, and the
regeneration must not disturb them.

### 1.3 Line-ending caveat that affects every digest

The repository has no `.gitattributes` and the local `core.autocrlf=true`, so the working
tree holds CRLF while the blobs hold LF. **The validators hash the bytes on disk**, so on a
CRLF checkout the Iteration 19–23 and closure validators fail on a pristine checkout of the
PR head as well. Every digest in this document is therefore computed over **git blob
bytes** (`git show <rev>:<path>`), never over the working tree. Reproduce with:

```bash
git -c core.autocrlf=false worktree add --detach <path> a8a8857
cd <path> && python -m benchmarks.validate_consolidated_closure_evidence --check
```

---

## 2. The pseudo-URI inventory

### 2.1 Method

The inventory is produced by a **deterministic script over the tracked JSON artifacts tree**,
not over a single run directory. Two properties matter:

* **It enumerates the whole tracked tree** — `git ls-files benchmarks/artifacts` — so the
  root-level `benchmarks/artifacts/latest_summary.json`, which sits *outside* every run
  directory and carries 33 of the 165 occurrences, cannot be missed. A script that only
  walks one run directory reports 132 and silently drops a fifth of the defect.
* **It reads the git blob store** — `git show <rev>:<path>` — not the working tree. With
  `core.autocrlf=true` the working tree holds CRLF while the published evidence is the blob
  (§1.3); an inventory computed over the working tree is not reproducible.

The script is read-only: nothing was modified, it only reads. It is not committed, because
the task restricts this change to this one Markdown file — copy it verbatim to reproduce:

```python
#!/usr/bin/env python3
"""Deterministic inventory of the fabricated ``modal-app://`` pseudo-URIs.

Reads every tracked JSON file under ``benchmarks/artifacts`` straight from the
git blob store (so the local ``core.autocrlf`` setting cannot change the
result) and reports, per file, how many ``modal-app://`` values it carries.

Usage:  python inventory_pseudo_uris.py <repo> [<rev>]
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
REV = sys.argv[2] if len(sys.argv) > 2 else "HEAD"
PUBLISHED_RUN = "benchmarks/artifacts/run_1794209615_70f5d22"
ROOT_SUMMARY = "benchmarks/artifacts/latest_summary.json"


def git(*args):
    return subprocess.run(["git", "-C", str(REPO), *args], check=True,
                          capture_output=True, text=True).stdout


def blob(path):
    return subprocess.run(["git", "-C", str(REPO), "show", f"{REV}:{path}"],
                          check=True, capture_output=True).stdout


def walk(node, path, out):
    if isinstance(node, dict):
        for k, v in node.items():
            walk(v, path + [str(k)], out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, path + [f"[{i}]"], out)
    elif isinstance(node, str) and node.startswith("modal-app://"):
        out.append("/".join(path))


tracked = [p for p in git("ls-files", "benchmarks/artifacts").splitlines()
           if p.endswith(".json")]

counts = {}
for path in sorted(tracked):
    hits = []
    walk(json.loads(blob(path).decode("utf-8")), [], hits)
    if hits:
        counts[path] = len(hits)

print(f"=== tracked JSON files under benchmarks/artifacts @ {REV} ===")
print(f"scanned: {len(tracked)}")
print()
print("=== pseudo-URI occurrences (modal-app://) ===")
run_total = root_total = other_total = 0
for path, n in counts.items():
    print(f"{path}\t{n}")
    if path.startswith(PUBLISHED_RUN + "/"):
        run_total += n
    elif path == ROOT_SUMMARY:
        root_total += n
    else:
        other_total += n
print()
print(f"RUN DIR SUBTOTAL ({PUBLISHED_RUN}): {run_total}")
print(f"ROOT-LEVEL SUBTOTAL ({ROOT_SUMMARY}): {root_total}")
print(f"TOTAL: {run_total + root_total}")
print()
print(f"OCCURRENCES OUTSIDE THE PUBLISHED TREE SCOPE: {other_total}")
```

The exact command — the revision is pinned, so the output below is reproducible and does not
depend on the state of the working tree:

```
$ python inventory_pseudo_uris.py D:\Install\I\Dropbox\Coding\GitHub\Agentic-security-RLVR a8a88575aed08c852b65e0fd3972846b9cf791dc
```

### 2.2 The count: 165, not 99 — and not 132

Verbatim output of the script above (19 paths, with their counts):

```
=== tracked JSON files under benchmarks/artifacts @ a8a88575aed08c852b65e0fd3972846b9cf791dc ===
scanned: 59

=== pseudo-URI occurrences (modal-app://) ===
benchmarks/artifacts/latest_summary.json	33
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/AC-01.json	6
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/BIZ-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/BRIDGE-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/DOS-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/ERC4626-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/FLASH-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/LIQ-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/ORACLE-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/PREC-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/REENT-01.json	6
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/SAFE-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/SAFE-02.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/SAFE-03.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/SAFE-04.json	4
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/SIG-01.json	2
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/STATE-01.json	4
benchmarks/artifacts/run_1794209615_70f5d22/reproducibility_manifest.json	33
benchmarks/artifacts/run_1794209615_70f5d22/summary.json	33

RUN DIR SUBTOTAL (benchmarks/artifacts/run_1794209615_70f5d22): 132
ROOT-LEVEL SUBTOTAL (benchmarks/artifacts/latest_summary.json): 33
TOTAL: 165

OCCURRENCES OUTSIDE THE PUBLISHED TREE SCOPE: 0
```

The script scanned all **59** tracked JSON files of the artifacts tree. Exactly **19** of them
carry a pseudo-URI, and the total is **165**.

| File class | Files | Occurrences | Tracked? |
|---|---|---|---|
| 16 target artifacts (`baseline_5/<TARGET>-01.json`) | 16 | **66** | yes |
| `reproducibility_manifest.json` | 1 | **33** | yes |
| `summary.json` (run dir) | 1 | **33** | yes |
| `latest_summary.json` (tree root) | 1 | **33** | yes (byte-identical to `summary.json`) |
| **Total** | **19** | **165** | all tracked |

Two ways of under-counting, both of which the script above avoids:

* The task's figure of **99** = 66 (targets) + 33 (manifest) counts two of the four files. It
  misses `summary.json` and `latest_summary.json`, which carry the same 33 occurrences.
* A script that walks **only the run directory** reports **132** — it misses the root-level
  `latest_summary.json` (33), which is not inside any run directory and is therefore invisible
  to a `run_*/` glob.

Both misses are material for the plan. `summary.json` and `latest_summary.json` are the
run-level views, and `latest_summary.json` is byte-identical to `summary.json`
(`sha256 = 3ff3993e0d6f7b50a070daff1504756435541057de83febef6e86b5136d6ba47`), so they are
one artifact with two copies — but both copies must be regenerated, or the tree contradicts
itself. The last line of the output is a deliberate guard: it proves that the older run
directories (`run_1794152785_e4e94fc`, `run_1794157194_864133b`, `run_1794174995_39eb396`,
§1.2) carry **zero** pseudo-URIs, so the scope of the defect is exactly the published run
plus its root-level mirror.

### 2.3 Per-target breakdown (66)

| Target artifact | Occurrences | Stages present |
|---|---|---|
| `AC-01.json` | 6 | inference, evm_sandbox, independent_replay |
| `REENT-01.json` | 6 | inference, evm_sandbox, independent_replay |
| `BIZ-01.json` | 4 | inference, evm_sandbox |
| `BRIDGE-01.json` | 4 | inference, evm_sandbox |
| `DOS-01.json` | 4 | inference, evm_sandbox |
| `ERC4626-01.json` | 4 | inference, evm_sandbox |
| `FLASH-01.json` | 4 | inference, evm_sandbox |
| `LIQ-01.json` | 4 | inference, evm_sandbox |
| `ORACLE-01.json` | 4 | inference, evm_sandbox |
| `PREC-01.json` | 4 | inference, evm_sandbox |
| `SAFE-01.json` | 4 | inference, evm_sandbox |
| `SAFE-02.json` | 4 | inference, evm_sandbox |
| `SAFE-03.json` | 4 | inference, evm_sandbox |
| `SAFE-04.json` | 4 | inference, evm_sandbox |
| `SIG-01.json` | 2 | inference only |
| `STATE-01.json` | 4 | inference, evm_sandbox |
| **Sum** | **66** | |

The count per target is `2 × (number of stages)`, because every target artifact stores the
same provenance block twice — once at the top level and once nested under
`tool_metadata`. The duplication is a consequence of the dataclass flattening in
`benchmarks/protocol.py`: `TargetExecutionArtifact.to_dict()` (`protocol.py:108`) emits
`modal_invocation_provenance` as a top-level field, while the adapter also places it inside
`tool_metadata`.

### 2.4 JSON paths (exhaustive shape)

**Four** distinct path shapes carry all 165 occurrences:

```
1. modal_invocation_provenance/stages/<stage>/durable_log_ref
2. tool_metadata/modal_invocation_provenance/stages/<stage>/durable_log_ref
3. adapters.baseline_5.per_target_provenance.<TARGET>\
       .modal_invocation_provenance/stages/<stage>/durable_log_ref
4. reproducibility_manifest_summary.adapters.baseline_5.per_target_provenance.<TARGET>\
       .modal_invocation_provenance/stages/<stage>/durable_log_ref
```

Their distribution matches the counts of §2.2 exactly:

| Shape | Where | Occurrences |
|---|---|---|
| 1 — top-level stage block | the 16 target artifacts | 33 |
| 2 — the same block under `tool_metadata` | the 16 target artifacts | 33 |
| 3 — the manifest's own per-target block | `reproducibility_manifest.json` | 33 |
| 4 — the manifest block embedded one level deeper | `summary.json` (33) + `latest_summary.json` (33) | 66 |
| | | **165** |

Shape 4 is not a fifth copy of the data: it is shape 3 wrapped in the summary's
`reproducibility_manifest_summary` envelope. That is why the two summaries are byte-identical
to each other and why `latest_summary.json` must be regenerated whenever `summary.json` is.

### 2.5 Value shape

Every one of the 165 occurrences has the form:

```
modal-app://ap-EDUitOwWeMrIdYbTh4kB63/<function>/<TARGET>/corr-<TARGET>-<epoch>-<8 hex>
```

e.g. `modal-app://ap-EDUitOwWeMrIdYbTh4kB63/inference/AC-01/corr-AC-01-1794209784-80afc62f`.

The shape is uniform: the app id is the hardcoded literal `ap-EDUitOwWeMrIdYbTh4kB63`, the
function name is the Modal function that was called, the target is the contract id, and the
correlation id is the run's correlation token. **No part of it is a provider-issued log
locator.** It is a client-side template. This is exactly what
`benchmarks/evidence_integrity.py:2664-2669` rejects:

```python
for legacy_key in ("durable_log_ref", "provider_log_uri", "log_uri"):
    legacy = stage.get(legacy_key)
    if isinstance(legacy, str) and legacy.startswith("modal-app://"):
        return False, (
            f"Modal provenance stage '{stage_name}' contains the synthetic log URI {legacy!r}"
        )
```

Note the asymmetry that produced F2: this check sits **inside** the stage loop of
`validate_modal_invocation_provenance`, *after* the checks that require
`app_id` / `function_call_id` / `container_id` on the stage. The published artifacts fail
the earlier check, so the URI check is never reached on them.

---

## 3. Why the upstream bytes cannot be taken

### 3.1 What upstream actually changed

Upstream rewrote the same run directory, not a different one:

```
$ git diff --stat d3201c9 origin/feat/empirical-benchmark-runner -- benchmarks/artifacts
 benchmarks/artifacts/latest_summary.json                            | 940 +++++-----
 .../run_1794209615_70f5d22/baseline_5/AC-01.json                   | 114 +--
 .../run_1794209615_70f5d22/baseline_5/BIZ-01.json                   |  98 +--
 ... (all 16 targets) ...
 .../run_1794209615_70f5d22/reproducibility_manifest.json            | 936 +++++-----
 .../run_1794209615_70f5d22/summary.json                             | 940 +++++-----
 23 files changed, 1693 insertions(+), 2719 deletions(-)
```

The upstream tree has **0** occurrences of `modal-app://` — the pseudo-URIs are gone. That
part of the task's finding 1 is correct and confirmed.

### 3.2 But upstream's bytes fail the iteration-line validators, and add a new defect

Validated against the iteration-line validators at the baseline commit:

```
### UPSTREAM bytes vs ITERATION-LINE validators ###
  validate_modal_invocation_provenance    -> FAIL | Modal provenance stage 'inference' is missing 'app_id'
  validate_remote_evm_toolchain_provenance -> FAIL | Remote EVM provenance fact 'forge_version' equals the
                                               legacy hardcoded constant 'forge 1.9.5 (92f59f6 ...)';
                                               provenance must be observed, not templated
  has_synthetic_modal_uri -> False

  upstream container_id: 'modal-cpu-c89a89057453'
  matches SYNTHETIC_CONTAINER_ID_RE: True
```

Three concrete defects in upstream's rewrite:

1. **No per-stage `app_id` / `function_call_id` / `container_id`.** Upstream's stages carry
   only `function_name`, `resource`, `invocation_id: NOT_AVAILABLE` and
   `durable_log_ref: NOT_AVAILABLE`. The iteration-line validator requires the three identity
   fields per stage (`evidence_integrity.py`, the `MODAL_PROVENANCE_STAGES` loop). Injecting
   them artificially moves the failure forward:

   ```
   upstream + app_id/fc injected -> FAIL | Modal provenance stage 'inference' is missing 'container_id'
   ```

2. **`container_id` is a synthetic value.** Upstream writes
   `"container_id": "modal-cpu-c89a89057453"` into `stages.independent_replay`. That matches
   `SYNTHETIC_CONTAINER_ID_RE = re.compile(r"^modal-(cpu|gpu|t4|h100)-[0-9a-f]{12}$")`
   (`evidence_integrity.py:119`) — the *exact* shape of the synthetic fallback the old client
   code generated. The validator rejects it explicitly:

   ```python
   if SYNTHETIC_CONTAINER_ID_RE.fullmatch(value):
       return False, (
           f"Modal provenance stage '{stage_name}' uses the synthetic container id {value!r}; "
           "the container identity must be the provider-issued worker id"
       )
   ```

   This is worse than the defect upstream was fixing: it is a *new* fabricated identity,
   wearing a more plausible shape.

3. **The four legacy constants survive.** Upstream's `remote_evm_provenance` still carries
   `remote_os: "Debian GNU/Linux 12 (bookworm)"`, `forge_version: "forge 1.9.5 (92f59f6 …)"`,
   `working_directory: "/tmp/aegis_sandbox"` — three of the four entries of
   `LEGACY_HARDCODED_EVM_FACTS` (`evidence_integrity.py:3523-3528`) — as flat strings with no
   observation source. Upstream only made `image_digest` honest (`NOT_AVAILABLE` with a
   reason) and renamed `image_tag` → `image_digest`. The task's finding 2 is therefore
   **confirmed**: the rename alone does not complete the provenance repair.

**Conclusion:** the upstream bytes are a *schema sketch*, not a solution. They show which
fields should become `NOT_AVAILABLE`; they cannot be published, because the iteration-line
validator refuses them — and one of the reasons it refuses them is a defect upstream
introduced.

---

## 4. The provenance contract: producer → transport → persistence → validator

### 4.1 The three identities and where they can honestly come from

The iteration line already contains the honest worker-side model in
`modal_app.py::capture_modal_runtime_identity` (line 445). This is the reference
implementation the plan reuses rather than reinvents.

| Field | Can it be observed? | Where it is observed | Notes |
|---|---|---|---|
| `function_call_id` | **Yes** | worker: `modal.current_function_call_id()` (`modal_app.py:498`) | The only genuinely worker-observed identity today. |
| `app_id` | **No** (worker) / **Yes** (client) | client: provider-issued `App.app_id` | `modal.running_app` is a **module** in Modal SDK 1.5.5, not callable — `modal_app.py:368-382`. The worker reports `NOT_AVAILABLE` with that exact reason (`modal_app.py:490`). |
| `container_id` | **No** (worker) / **Yes** (client) | client: `ModalProvider.containers_of_app()` / `task_app_id()` (`modal_provider.py:136,160`) | `MODAL_WORKER_ID` is the SDK's `worker_id` *configuration setting* (internal debugging use), `HOSTNAME` is a generic hostname — neither is provider-issued. Worker reports `NOT_AVAILABLE` (`modal_app.py:522`). |

The client-side resolution path exists and is documented in `benchmarks/modal_provider.py`:

- `call_graph_inputs(function_call_id)` — the provider's call graph; each entry carries the
  `function_call_id` **and** the `container_id` (`task_id`) that executed it
  (`modal_provider.py:104-132`).
- `containers_of_app(app_id)` — the provider's container listing; `task_id` **is** the
  container id (the SDK calls it `get_old_container_ids()`).
- `task_app_id(container_id)` — the provider's own record of the app↔container relation; an
  independent second cross-check.

This is the answer to the task's finding 3: the schema incompatibility is real, but the
missing piece is **already implemented and simply not wired into the artifact path**.

### 4.2 The current published artifacts against the current contract

The published target artifacts carry a *pre-Iteration-14* flat schema. Measured:

```
### CURRENT (iteration-line) published bytes vs same validators ###
  validate_modal_invocation_provenance    -> FAIL | Modal provenance stage 'inference' is missing 'function_call_id'
  validate_remote_evm_toolchain_provenance -> FAIL | Missing remote EVM provenance fact: 'image_digest'
  has_synthetic_modal_uri -> True
    remote_os        = "Debian GNU/Linux 12 (bookworm)"
    remote_platform  = "linux"
    image_tag        = "debian:12-slim-foundry"
    forge_version    = "forge 1.9.5 (92f59f6 2026-11-04T00:23:44.821105000Z)"
    solc_versions    = ["0.8.20", "0.8.24"]
    exact_forge_argv = ["forge", "test", "--offline", "--json", "-vvvv"]
    working_directory= "/tmp/aegis_sandbox"
```

Against the required contract (`REMOTE_EVM_REQUIRED_FACTS`, `evidence_integrity.py:3510-3519`)
the published block is wrong in five ways at once:

| Required fact | Published value | Problem |
|---|---|---|
| `remote_os` | `"Debian GNU/Linux 12 (bookworm)"` | legacy constant; accepted only via `EVM_FACTS_WITH_COINCIDENT_LEGACY_VALUE`, but with **no** `source` — the source token `os-release` is required (`EVM_FACT_REQUIRED_SOURCE_TOKENS:3536`) |
| `image_tag` | `"debian:12-slim-foundry"` | **wrong key** — the contract requires `image_digest`; and a mutable tag is rejected outright (`MODAL_IMAGE_ID_RE`, `evidence_integrity.py:104`) |
| `forge_version` | `"forge 1.9.5 (…)"` | legacy constant → rejected (`LEGACY_HARDCODED_EVM_FACTS`) |
| `working_directory` | `"/tmp/aegis_sandbox"` | legacy constant → rejected |
| `solc_versions`, `exact_forge_argv`, `compiler_settings` | flat values | no `source` → rejected |
| *(absent)* | — | `remote_platform` missing as a sourced fact; `image_digest` missing entirely |

Every one of these is a *flat* value. The contract requires each fact to be an
`observed(value, source=…)` / `not_available(reason, evidence_ref=…)` envelope
(`evidence_integrity.py:187-249`).

### 4.3 The source of observation for each required field

The contract already names the required observation source per fact
(`EVM_FACT_REQUIRED_SOURCE_TOKENS`, `evidence_integrity.py:3535-3544`). Mapping each to a
concrete command or file that a worker can run today:

| Fact | Required source token | Concrete observation inside the Modal worker | Reachable today? |
|---|---|---|---|
| `remote_os` | `os-release` | read `/etc/os-release` → `PRETTY_NAME` | **Yes** — trivial in the worker |
| `remote_platform` | `os.name`, `platform.` | `platform.uname()` / `os.name` | **Yes** |
| `image_digest` | `image_id` | the provider-issued Modal image id — `im-XXXXXXXX`; **not** observable from inside the container (no OCI manifest digest in the sandbox), so it is a **client-side** fact obtained from the provider's image record | **No** (worker) → must be `NOT_AVAILABLE` with reason, or client-observed |
| `forge_version` | `forge --version` | run `forge --version` in the worker, capture stdout | **Yes** — the worker already runs `forge test` |
| `solc_versions` | `forge config` | `forge config` → `solc` / `solc_version` | **Yes** |
| `exact_forge_argv` | `argv` | the exact `argv` the worker passed to `forge` | **Yes** — the worker builds it |
| `working_directory` | `cwd` | `os.getcwd()` at the moment of the forge invocation | **Yes** |
| `compiler_settings` | `forge config` | `forge config` output | **Yes** |
| `app_id` | — | client-side: `App.app_id` of the running app | client only |
| `function_call_id` | — | worker: `modal.current_function_call_id()` | **Yes** |
| `container_id` | — | client-side: provider call graph + container listing + task record | client only |
| billing attribution | — | raw billing export → `validate_billing_attribution` | **Yes** — the export is published |

**The decisive observation for the plan:** eight of the eleven remote-EVM facts are
genuinely observable inside the worker today with one command each, and the three identity
facts split cleanly into worker-observed (`function_call_id`) and client-observed
(`app_id`, `container_id`). Nothing needs to be fabricated — and `image_digest` is the one
fact that genuinely cannot be observed from inside the container, which is exactly why the
honest `NOT_AVAILABLE` contract exists.

### 4.4 The billing attribution path

| Stage | Mechanism |
|---|---|
| Producer | `benchmarks/regenerate_billing_join_table.py` → `build_billing_attribution` (`evidence_integrity.py:~3050-3157`) |
| Persistence | `benchmarks/evidence/modal_billing_join_table.json`, schema **3.0.0** |
| Raw input | `benchmarks/evidence/modal_billing_report_raw.json` (`sha256 = 1529b1b9…`) |
| Validator | `validate_billing_attribution(attribution, line_items, known_app_ids=…)` (`evidence_integrity.py:3160`) |
| Policy | `PROVIDER_JOIN_FIELDS = ("invocation_id", "function_call_id", "task_id")` (`evidence_integrity.py:2807`); `aggregate_bucket_allocation: "FORBIDDEN"`; target-level cost is `null` with `cost_status = "UNATTRIBUTED_NO_INVOCATION_LEVEL_JOIN"` unless an exact unique provider join resolves to exactly one raw line item |

The published join table already satisfies this contract: 16 target rows, each with
`cost_usd: null` and a machine-readable reason. Its references split into exactly two
groups, and they must not be conflated:

| Group | Where | Count | What the digest pins |
|---|---|---|---|
| harness references | `canonical_run_app_session.evidence_ref` (1) + `target_level[*].app_id_evidence_ref` (16) | **17** | `benchmarks/evidence/modal_control_harness_validation.json` (`sha256 = 7a56eadb…`) |
| raw-export reference | `source_raw_export.path` + `source_raw_export.sha256` | **1** | `benchmarks/evidence/modal_billing_report_raw.json` (`sha256 = 1529b1b9…`) |

The 17 harness references all pin the **same** file, so they all change together when the
harness validation file is regenerated (§7.3). The single raw-export reference pins the raw
billing export, which is the *input* of the join table, not a product of the run: if
`modal_billing_report_raw.json` is not re-exported, its digest does not change and
`source_raw_export.sha256` must stay `1529b1b9…`.

The billing join therefore **does not need to be regenerated** for a provenance-schema
migration — only the 17 harness digests change, and only if the harness validation file
changes (§7).

---

## 5. The target schema (the contract to implement)

This is the third contract: not the iteration line's current schema, and not upstream's, but
the intersection that satisfies both validators.

### 5.1 Stage block

```
stages.<stage> = {
  "attempted":        bool,
  "function_name":    str | null,
  "resource":         str,
  "app_id":           observed(...) | not_available(...),   # client-observed
  "function_call_id": observed(...) | not_available(...),   # worker-observed
  "container_id":     observed(...) | not_available(...),   # client-observed
  "evidence_ref":     {path, sha256, byte_length},          # the stage's own bytes
}
```

**No `durable_log_ref`, no `provider_log_uri`, no `log_uri` key at all.** The three legacy
keys are removed by the producer rather than set to `NOT_AVAILABLE`, because the validator
rejects them by *presence with a `modal-app://` value* — but a key that still exists invites
the next producer to fill it. The validator's `legacy_key` loop stays as a second line of
defence.

### 5.2 Run-level block

```
modal_invocation_provenance = {
  "app_session_id":   observed(...) | not_available(...),   # renamed; see 5.3
  "target_id":        str,
  "correlation_id":   str,
  "invocation_id":    observed(...) | not_available(...),
  "stages":           { ... },
}
```

### 5.3 On `modal_app_id` → `app_session_id`

**This plan does not decide the name.** The rename upstream proposes is *semantically
better*, but choosing it is the maintainer's call, and it stays open as **Q1** (§11.2). What
*is* settled here is everything except the spelling:

1. **The semantics.** Whatever the field is called, its value is the **provider-issued
   application id** of the running app — a value that identifies the app, not the session.
   Upstream's own value is the same literal `ap-EDUitOwWeMrIdYbTh4kB63` in every row, which
   confirms it is the app id. `app_session_id` would therefore be a slightly imprecise name
   for an application id; `app_id` is the accurate one.
2. **The shape.** The field carries the §5.5 `observed()` / `not_available()` envelope like
   every other identity fact. A bare string is not acceptable under D3 under any of the three
   names in Q1.

So the *contract* of the field is fixed by D3; only the *spelling* is open. The schema
example in §5.2 uses `app_session_id` solely because that is the spelling upstream proposed —
if Q1 is answered differently, the field is renamed and nothing else in §5 changes.

### 5.4 Remote-EVM block

Every one of the eight required facts becomes a sourced envelope:

```
remote_evm_provenance = {
  "remote_os":         observed(value, source="/etc/os-release: PRETTY_NAME", observed_by="worker"),
  "remote_platform":   observed(value, source="platform.uname()",             observed_by="worker"),
  "image_digest":      not_available(reason=…, evidence_ref=…) | observed("im-XXXXXXXX", source="modal image id", observed_by="client"),
  "forge_version":     observed(value, source="forge --version",              observed_by="worker"),
  "solc_versions":     observed(value, source="forge config → solc_version",  observed_by="worker"),
  "exact_forge_argv":  observed(value, source="argv of the forge invocation",  observed_by="worker"),
  "working_directory": observed(value, source="os.getcwd() at forge invocation", observed_by="worker"),
  "compiler_settings": observed(value, source="forge config",                 observed_by="worker"),
}
```

The legacy constants disappear because the values are now *read*, not templated. If the
worker's real `forge --version` output happens to equal the legacy string, the validator
accepts it — because the coincidence is decided by the source, not the value
(`EVM_FACTS_WITH_COINCIDENT_LEGACY_VALUE` covers `remote_os` / `remote_platform`; for
`forge_version` and `working_directory` the coincidence is now harmless because the value is
sourced, which is the intent of the comment at `evidence_integrity.py:3546-3548`).

**No value in this block may be copied from the published artifacts.** The producer must
*measure* them on the run.

### 5.5 The `NOT_AVAILABLE` contract

A field that cannot genuinely be observed is recorded as:

```python
not_available(
    "<the exact reason, naming the API that was tried and what it returned>",
    absence_kind=one of ABSENCE_KINDS
                 ("PROVIDER_FIELD_OMITTED", "STAGE_NOT_ATTEMPTED",
                  "STAGE_EXECUTED_NO_RUNTIME_ENVELOPE",
                  "CLIENT_NEVER_CAPTURED_FIELD",
                  "STAGE_ATTEMPT_FAILED_NO_RESPONSE"),   # evidence_integrity.py:550-556
    observed_by="worker" | "client",
    evidence_ref=build_evidence_ref(path_to_immutable_artifact),
)
```

The `evidence_ref` is mandatory for a field the provider *should* have reported: the
validator resolves the digest against the referenced bytes and refuses a reason string
alone (the Iteration 15 rule). The `observed_by` side distinguishes "the worker could not
see it" from "the client did not look" — the Iteration 20 rule
(`OBSERVATION_SIDE_WORKER = "worker"`, `OBSERVATION_SIDE_CLIENT = "client"`,
`evidence_integrity.py:137,140`).

Only `PROVIDER_FIELD_OMITTED` may claim that the provider did not report a field; the
other four kinds describe a situation in which the provider was never asked
(`ABSENCE_KINDS_THAT_MAY_CLAIM_PROVIDER_OMISSION`, `evidence_integrity.py:560`). The
validator enforces this: a fact whose reason blames the provider while its own stage
evidence says the field was never requested is rejected.

---

## 6. Validator call-path analysis

### 6.1 Where synthetic-URI detection currently happens

| Detector | Definition | Enforced on |
|---|---|---|
| `has_synthetic_modal_uri(payload)` | `evidence_integrity.py:2784-2794` | **nowhere authoritative** — see §6.2 |
| inline `legacy_key` loop | `evidence_integrity.py:2664-2669` | inside `validate_modal_invocation_provenance` — **yes**, but only after the identity-field checks |
| `FORBIDDEN_SYNTHETIC_CONTAINER_IDS` | `evidence_integrity.py:107-114` | `validate_modal_invocation_provenance` (stage `container_id`) and the replay envelope |
| `SYNTHETIC_CONTAINER_ID_RE` | `evidence_integrity.py:119` | same two places |

### 6.2 The detector that is not enforced

`has_synthetic_modal_uri` is called in exactly three validator modules — and in all three
it is a **diagnostic field**, not a verdict:

```
benchmarks/validate_iteration14_evidence.py:163
    synthetic_uri_present=has_synthetic_modal_uri(join_table),
benchmarks/validate_iteration15_evidence.py:228
    synthetic_uri_present=has_synthetic_modal_uri(join_table),
benchmarks/validate_iteration16_evidence.py:316
    synthetic_uri_present=has_synthetic_modal_uri(join_table),
```

`validate_iteration14_evidence.py:152-165` shows the shape: the check's `ok`/`error` come
from `validate_billing_attribution(...)`; `synthetic_uri_present` is an *extra key* on the
report entry. A `True` there does not fail the check. The published reports confirm the
field is informational — `"synthetic_uri_present": false` in iterations 14–18.

**It is also scoped to the join table, not to the artifacts.** The 165 pseudo-URIs live in
the target artifacts and the manifest; the join table carries none. So the one detector that
looks at the whole payload is pointed at the one file that has no pseudo-URI.

Iterations 17, 18, 19–23 and the closure validator do not call it at all.

### 6.3 Does the reproducibility-manifest path reject synthetic URIs?

**No.** `benchmarks/protocol.py::validate_manifest_git_integrity` (line 314) validates the
`git` block only — commit sha shape, dirty flag, run-dir suffix. It never walks the
manifest payload. No validator in the repository applies a synthetic-URI check to a
reproducibility manifest.

### 6.4 Does the billing-join path reject synthetic URIs?

**Not on the authoritative path.** `validate_billing_attribution` (`evidence_integrity.py:3160`)
checks app-id existence, exact-once accounting of raw line items, aggregate reconciliation,
target-cost-without-join, double attribution, and machine-readable reasons. It contains
**no** synthetic-URI check.

The rejection of a pseudo-URI in the join table today comes from the *ported upstream test*
(`tests/test_real_benchmark_execution.py:3311-3315`), which asserts
`has_synthetic_modal_uri(bad_uri_join) is True` — a test, not a validator. The upstream
reconciliation document (§3.5 of
`benchmarks/evidence/upstream_reconciliation_change_impact_matrix.md`) describes it as
"detected by `has_synthetic_modal_uri`" — correct as a statement about the *test*, but the
**validator does not enforce it**.

This is precisely the distinction the task asks for: *"do not claim a detector is enforced
by a validator unless the call path proves it."*

### 6.5 Required call-path changes

| # | Change | File | Rationale |
|---|---|---|---|
| **C1** | Apply `has_synthetic_modal_uri` to **every target artifact** and make it a verdict, not a diagnostic: `ok = ok and not has_synthetic_modal_uri(artifact)`. | `validate_iteration14..18_evidence.py` (per-target loop) | the pseudo-URIs live in the artifacts; today nothing checks them there |
| **C2** | Apply it to the **reproducibility manifest** and to `summary.json` / `latest_summary.json`, with the same verdict semantics. | new call in the same validators, or a shared helper in `evidence_integrity.py` | §6.3 — nothing checks the manifest today |
| **C3** | Apply it to the **join table** as a verdict inside `validate_billing_attribution` itself, so the enforcement lives in the validator and not only in a test. | `evidence_integrity.py::validate_billing_attribution` | §6.4 |
| **C4** | Keep the inline `legacy_key` loop as the second line of defence. | `evidence_integrity.py:2664` | already correct; do not weaken it |
| **C5** | Add `synthetic_uri_present` as a *rejection reason* in the report, so a failure explains itself. | all validators | diagnosability |

### 6.6 Required negative tests

Each of these must fail **before** the fix and pass **after**:

| # | Test | Proves |
|---|---|---|
| **T1** | a target artifact with `modal-app://` in `stages.inference.durable_log_ref` → target FAILED, error names the URI | C1 |
| **T2** | a reproducibility manifest with a `modal-app://` value → FAILED | C2 |
| **T3** | `summary.json` / `latest_summary.json` with a `modal-app://` value → FAILED | C2 |
| **T4** | a join table with a `modal-app://` in `target_level[0]` → `validate_billing_attribution` returns `False` with the URI named | C3 (today it returns `True`) |
| **T5** | an upstream-shaped artifact with `container_id = "modal-cpu-c89a89057453"` → FAILED by `SYNTHETIC_CONTAINER_ID_RE` | F3 — prevents the upstream bytes from being adopted |
| **T6** | an upstream-shaped artifact with `forge_version` = the legacy constant and **no** source → FAILED | F3 / §3.2(3) |
| **T7** | an upstream-shaped artifact with `stages.inference` lacking `app_id`/`function_call_id`/`container_id` → FAILED | F3 / §3.2(1) |
| **T8** | the regenerated artifacts pass `validate_modal_invocation_provenance` **and** `validate_remote_evm_toolchain_provenance` | the whole point |
| **T9** | the *published* artifacts, if not regenerated, still fail — the historical FAILED state is preserved | §9.4 |
| **T10** | the effective `--run-dir` default of each of the historical validators (14–18) is still `benchmarks/artifacts/run_1794209615_70f5d22` — a repointed default fails the suite | §8.2.4 (e) |
| **T11** | no code path selects the authoritative run by recency: a **newer** run directory in the tree is not selected, because the selection is a literal path | §8.2.4 (b) |

---

## 7. SHA-256 / reference impact matrix

### 7.1 What the published evidence actually pins

Computed over git blobs at `a8a8857`:

| Pinned file | sha256 (blob) |
|---|---|
| `benchmarks/evidence/modal_control_harness_validation.json` | `7a56eadb65803946c0fb0d8afcf83f58c839638b79d83c11ac3d1d1c2c7468e5` |
| `benchmarks/evidence/modal_billing_join_table.json` | `8f62a23d2d25bb3ab550b4e73d69952b7efac2f7d1447a987651c55eecbbf4a0` |
| `benchmarks/evidence/modal_billing_report_raw.json` | `1529b1b90ad609332d77837e3ee2f13e674dcdb90db401324f2b710e7662fc18` |
| `benchmarks/artifacts/run_1794209615_70f5d22/reproducibility_manifest.json` | `0d8ec80175998598596f53c17976468e5618e5f664e55fb1294549a860f96972` |
| `benchmarks/artifacts/run_1794209615_70f5d22/summary.json` | `3ff3993e0d6f7b50a070daff1504756435541057de83febef6e86b5136d6ba47` |
| `benchmarks/artifacts/latest_summary.json` | `3ff3993e0d6f7b50a070daff1504756435541057de83febef6e86b5136d6ba47` (identical to `summary.json`) |

Upstream's versions of the first two: `4a06bbc4…` and `6fb30d84…` — both differ, which is
why the merge could not take the upstream bytes.

### 7.2 Reference graph (who pins whom)

```
modal_billing_join_table.json ──x17──> modal_control_harness_validation.json
                    │              (1 canonical_run_app_session.evidence_ref
                    │               + 16 target_level[*].app_id_evidence_ref)
                    │
                    └──x1──> modal_billing_report_raw.json
                              (source_raw_export.path + .sha256 — the raw export,
                               NOT the harness validation file)
                                 
modal_control_harness_validation.json ──> 16× <TARGET>_stdout.txt   (stdout_path + stdout_sha256)
                                   ──> 16× <TARGET>_stderr.txt    (stderr_path + stderr_sha256)
                                   ──> 16× <TARGET> .sol source   (input_sha256 — digest only,
                                   │                              the path is NOT recorded)
                                   ──>  2× replay stdout/stderr   (replay_evidence.*_sha256 for
                                   │                              AC-01 and REENT-01 only; no path)

reproducibility_manifest.json ──> 16× baseline_5/<TARGET>-01.json  (artifact_files[].sha256)
       ──> 16× <TARGET>_stdout.txt          (artifact_files[].sha256)
       ──> 16× <TARGET>_stderr.txt           (artifact_files[].sha256)
                              (the 4 *_replay_*.txt files are NOT pinned by the manifest)

iteration16/17/18_validation_evidence.json ──x1 each──> their 4 rehearsal stage-evidence files
iteration19_validation_evidence.json ──x2──> CPU-SMOKE-01_stage_evidence_cpu_smoke.json
iteration20_validation_evidence.json ──x2──> ITER20-01_stage_evidence_evm_sandbox.json
iteration21/22/23_validation_evidence.json ──x2──> ITER21-01_stage_evidence_evm_sandbox.json
```

Two facts in that graph are easy to get wrong; both were measured, not inferred:

* The harness validation pins **16** Solidity sources, not 17. Each of the 16 targets carries
  an `input_sha256` that equals the SHA-256 of its own `.sol` file — 16 of 16 matched against
  the 32 tracked files of `benchmarks/targets/solidity/`. The *path* is not recorded, only the
  digest. Its `replay_evidence.harness_sha256` is the digest of the forge *harness*, not of a
  `.sol` file.
* The 4 `*_replay_stdout.txt` / `*_replay_stderr.txt` files are pinned by the harness — for
  AC-01 and REENT-01, as digests without paths — but **not** by the manifest.

### 7.3 The blast radius of a regeneration

**Pinned by digest — the 16 target artifacts.** `reproducibility_manifest.json →
adapters.baseline_5.artifact_files` holds 48 `(relative_path, size_bytes, sha256)` records:
the 16 target JSONs and the 32 stdout/stderr files. All 16 JSON digests equal the SHA-256 of
the corresponding git blob. Regenerating the target artifacts therefore does **not** leave the
manifest untouched — the manifest must be re-pinned to the new bytes, and the manifest's own
digest changes with it.

**Pinned by digest — `modal_control_harness_validation.json`.** It pins the 32 stdout/stderr
files (path + digest) and the 16 Solidity sources (digest only). If the regeneration re-runs
the benchmark, the stdout bytes change, so the harness validation file changes, so:

- its own sha changes from `7a56eadb…` to a new value;
- the join table's **17 harness references** (`canonical_run_app_session.evidence_ref` + the
  16 `target_level[*].app_id_evidence_ref`) must be updated to the new digest;
- the join table's own sha changes from `8f62a23d…`;
- the closure validator's P6.15 re-checks the *stage evidence* digest, and the Iteration
  19–23 validators re-check their own pins.

**Unchanged — the raw billing export.** `modal_billing_report_raw.json` is the raw billing
export — it is the *input*, not the product of a run, so it does not change unless a new
billing period is exported. Consequently the join table's single `source_raw_export` entry
keeps `sha256 = 1529b1b9…`; it must **not** be "updated to the new digest", because there is
no new digest for it. The Solidity sources do not change. The Iteration 16–18 rehearsal
artifacts are produced by a separate rehearsal path and stay valid.

**A pre-existing inconsistency the regeneration must not inherit.** The two published files
that pin the same 32 stdout/stderr files currently **disagree on 15 of them**:

| Producer | Convention | Result over the 32 pinned files |
|---|---|---|
| `modal_control_harness_validation.json` | SHA-256 over the **LF** blob bytes | 32 of 32 match the blob digest |
| `reproducibility_manifest.json` | SHA-256 over **CRLF** bytes for the stdout files | 17 match (the 16 empty stderr files + the empty `SIG-01_stdout.txt`), **15 disagree** |

The 15 disagreeing files are exactly the non-empty `<TARGET>_stdout.txt`; their recorded
`size_bytes` in the manifest is the CRLF length, while the JSON files' `size_bytes` is the LF
length. Nothing currently compares the two files against each other, so the contradiction is
latent. A regeneration must pin every digest it publishes over the **same** bytes — the git
blob bytes (§1.3) — and re-pin the manifest accordingly; otherwise the new evidence would
inherit the same divergence (D10).

### 7.4 Impact matrix

| # | File | Digest pinned by | Changes? | Action |
|---|---|---|---|---|
| 1 | 16 × `<TARGET>-01.json` **in the new run dir** | the new run's `reproducibility_manifest.json` → `artifact_files` ×1 each | **yes** | regenerate in the new run directory |
| 2 | `reproducibility_manifest.json` **in the new run dir** | embedded byte-for-byte in the new `summary.json` / `latest_summary.json` | **yes** | regenerate; re-pin all 48 `artifact_files` digests over blob bytes (D10) |
| 3 | `summary.json` **in the new run dir** | — | **yes** | regenerate |
| 4 | `latest_summary.json` (tree root) | — | **yes** | regenerate — stays the byte-identical mirror of the **authoritative** run's `summary.json` (D12) |
| 5 | 16 × `<TARGET>_stdout.txt` (new run dir) | new harness ×1 each **and** new manifest ×1 each | **yes** | regenerate with the run; pin over blob bytes (D10) |
| 6 | 16 × `<TARGET>_stderr.txt` (new run dir) | new harness ×1 each **and** new manifest ×1 each | possibly | regenerate with the run |
| 7 | 4 × `*_replay_stdout.txt` / `*_replay_stderr.txt` (new run dir) | new harness ×1 each, for AC-01 and REENT-01 only (**not** the manifest) | possibly | regenerate with the run |
| 8 | `modal_control_harness_validation.json` | join table ×17 | **yes** | regenerate, then re-pin |
| 9 | `modal_billing_join_table.json` | — (validated against the raw export) | **yes** — the 17 harness digests only | update those 17 digests; keep schema 3.0.0 and `source_raw_export` untouched |
| 10 | `modal_billing_report_raw.json` | join table ×1 (`source_raw_export.sha256`) | **no** | keep as-is; its digest stays `1529b1b9…` unless the billing window changes |
| 11 | `iteration14..18_validation_evidence.json` | — (published verdicts) | **no** | **immutable** (D8): the published `FAILED (0/16)` reports stay exactly as they are |
| 12 | the new run's iteration report (a **new** file) | the new run's stage-evidence files | **yes** | new file — the *replacement* evidence (D8) |
| 13 | `iteration19..23_validation_evidence.json` | rehearsal/capture stage files | **yes** (if the capture is redone) | regenerate |
| 14 | `consolidated_closure_validation_evidence.json` | — | **yes** | regenerate; must stay 21/21 PASSED, with the 14–18 rows of `HISTORICAL_EVIDENCE` unchanged and a new row for the new iteration (D8) |
| 15 | `benchmarks/targets/solidity/*.sol` | new harness ×1 each (`input_sha256`) | no | keep |
| 16 | `iteration16..18_producer_rehearsal/*` | iteration16..18 evidence | no | keep |
| 17 | the published run `run_1794209615_70f5d22/` | its own manifest ×1, harness ×32, join table ×17 | **no** | keep in place, byte-for-byte, as the historical evidence (D9) |

Rows 11 and 17 are the historical-evidence rows, and they are the ones a careless
regeneration would violate. The old FAILED reports and the old run tree stay exactly as
published: the old run's 16 target artifacts keep their 66 pseudo-URIs, because that is the
historical record of the defect — editing or deleting them would be rewriting history (D8).
The invariant "no `modal-app://` in the published evidence" therefore becomes **scoped**: it
holds for the authoritative run (D9) and is reported per run, not globally.

The previous content of `latest_summary.json` is not lost by row 4: the old run's own
`summary.json` is byte-identical to it and stays in the old run directory, and the old bytes
remain in the commit history. The mirror is not a matter of taste but decision **D12**
(§11.1): the root-level `latest_summary.json` stays a byte-identical copy of the
**authoritative** run's `summary.json`, and the question "mirror or pointer" is therefore
closed — the pointer option is not part of this plan.

---

## 8. The atomic regeneration sequence

### 8.1 Preconditions (all must hold before step 1)

1. Explicit maintainer authorisation for a regeneration iteration (this plan is a proposal).
2. A clean LF checkout: `git -c core.autocrlf=false worktree add --detach <path> <branch>`.
3. `foundry`/`forge` on `PATH` in the worker image; the local machine does not need it.
4. Modal credentials for the target workspace; the app name `aegis-rlvr-security` is the
   one recorded in the published artifacts.
5. A cost ceiling for every compute step, and a separate approval for every compute step —
   §8.2.5. The monetary ceiling of the paid steps is open question **Q5** (§11.2), still
   unanswered; the CPU smoke has its own, smaller ceiling. **No** step starts without its own
   ceiling and its own approval: an approval for R4 approves R4 and nothing else.
6. A **detached worktree** pinned at the producer commit `P` for the execution steps R3, R3b
   and R4 (§8.2.6), so that the manifest, the run directory, the report and the closure all
   carry the same SHA.

### 8.2 The sequence

Each step is atomic: it either completes and is committed, or the tree is rolled back to
the last committed step (§8.4).

| Step | Action | Produces | Gate before proceeding |
|---|---|---|---|
| **R0** | Branch `iter-24/evidence-regeneration` from the authorised base. | — | clean tree, base SHA recorded |
| **R1** | Implement the §5 schema in the producer (`adapters.py`, `modal_app.py`, `benchmark_runner.py`) and the §6.5 validator changes. | code only | unit tests green; **no** published file touched; the commit of R1 is the producer commit **`P`** — no commit after it may touch the producer paths (§8.2.6, §9.3) |
| **R2** | Add the §6.6 negative tests T1–T9. | tests | each test fails on the pre-fix code and passes on the post-fix code (proven by running both revisions) |
| **R3** | **CPU-only plumbing smoke** on one target (`AC-01`), limited to the stages that need no GPU: `evm_sandbox` and `independent_replay`. The `inference` stage is **not attempted** and is therefore **absent** from the smoke artifact. | one throwaway artifact outside `benchmarks/evidence/` | the §8.2.1 gate: every stage **present** in the artifact satisfies the §5 contract; **nothing is claimed about the stages that are absent**; the caps and the approval **A-R3** of §8.2.5 hold before the first container starts |
| **R3b** | **Inference-plumbing smoke** — one GPU-backed inference call for one target, to obtain a real worker-observed `function_call_id` and the client-resolved `app_id` / `container_id` for that call. | one throwaway artifact outside `benchmarks/evidence/` | the §8.2.2 gate; **separately authorised** (**A-R3b**), because it spends GPU time and Modal credits; its caps of §8.2.5 are fixed **before** the first call |
| **R4** | Authorised live run: 16 targets, the same provider configuration as the published run (`modal_h100`, `qtum/Qwen3-Coder-30B-A3B-Audit`, `--hypotheses=3`), executed from the detached worktree at `P` (§8.2.6). | a **new** run directory `run_<epoch>_<P[:7]>/` | every stage's provenance is observed-or-explicitly-`NOT_AVAILABLE`; the run completes; the directory suffix equals the manifest's `git.commit_sha[:7]` (§8.2.3); the manifest's SHA is `P` (§8.2.6); the approval **A-R4** and its ceiling hold |
| **R5** | Verify the new run **before** it becomes published: run the §5 validators over the new run dir; assert `has_synthetic_modal_uri` is false for every file; assert no `SYNTHETIC_CONTAINER_ID_RE` match anywhere. | a verification transcript | all assertions hold |
| **R6** | **Publish the new run tree additively** (D9): the new run's 16 target artifacts, its manifest, its `summary.json`, and the root-level `latest_summary.json` — which becomes the byte-identical mirror of the **new** run's `summary.json`. The published run `run_1794209615_70f5d22/` is **not** modified, moved or deleted. | new published bytes | `git diff --stat` shows only the expected files; `latest_summary.json` is byte-identical to the new run's `summary.json`; the old run directory is untouched in the diff |
| **R7** | Regenerate `modal_control_harness_validation.json` (re-pin the 32 stdout/stderr digests and the 16 `input_sha256` values over blob bytes). | new digest | the file validates against the new run dir |
| **R8** | Regenerate `modal_billing_join_table.json` (schema 3.0.0 preserved; **only the 17 harness digests change** — `source_raw_export` keeps `1529b1b9…` unless the raw export was re-exported). | new digest | `python -m benchmarks.regenerate_billing_join_table --check` → PASSED; `validate_billing_attribution` → PASSED |
| **R9** | **Do not regenerate** `iteration14..18_validation_evidence.json`: they are immutable (D8). Produce instead the **new run's own iteration report** from the new run directory. | a new report file | the old reports are byte-identical in the diff; the new report's verdict is the validator's output for the new run |
| **R10** | Regenerate `iteration19..23_validation_evidence.json` and `consolidated_closure_validation_evidence.json`; extend the closure validator's `HISTORICAL_EVIDENCE` with a row for the new iteration, leaving the Iterations 14–18 rows untouched. | new verdicts | iterations 19–23 `PASSED`; closure `21/21 PASSED` with **both** the old FAILED rows and the new row present |
| **R11** | Full test suite; then the complete validator sweep. | transcript | `pytest -q` green; every validator exits 0 with the expected verdict string |
| **R12** | Open a Draft PR with the full before/after inventory and the verifier transcript. | reviewable diff | maintainer approval |

### 8.2.1 The R3 gate, stated exactly

R3 exists to prove the **plumbing** of the §5 contract — not the inference identity. The
distinction is enforced by the artifact itself: the smoke artifact contains the stages
`evm_sandbox` and `independent_replay` and **no `inference` stage**.

**What R3 must show.**

1. **The stage block of every stage that is present** carries `app_id`, `function_call_id` and
   `container_id` as `observed()` / `not_available()` envelopes (§5.1, §5.5) — no bare
   strings, no `modal-app://`, and no `durable_log_ref` / `provider_log_uri` / `log_uri` key
   at all.
2. **Every `not_available` envelope carries** a reason, an absence kind from `ABSENCE_KINDS`,
   an `observed_by` side, and an `evidence_ref` whose digest verifies. The last requirement
   means the validator must be called **with an evidence root**:
   `validate_modal_invocation_provenance(artifact, evidence_root=<smoke run dir>/baseline_5)`.
   Without `evidence_root` the referenced bytes cannot be resolved and the validator rejects
   **every** `NOT_AVAILABLE` fact with "no evidence root was provided"
   (`evidence_integrity.py:428-456`). The published Iteration 14 validator calls it *without*
   that argument (`validate_iteration14_evidence.py:185`), while Iteration 15 passes
   `evidence_root=run_dir / baseline_id` (`validate_iteration15_evidence.py:254`) — the smoke
   must follow the latter form.
3. **The remote-EVM block** of the smoke artifact passes
   `validate_remote_evm_toolchain_provenance(artifact)` (`evidence_integrity.py:3557`): all
   eight facts of `REMOTE_EVM_REQUIRED_FACTS` (`evidence_integrity.py:3510`) are sourced
   `observed(...)` envelopes, or explicit `not_available(...)` with a reason and an evidence
   reference.
4. **The run-level block** validates: the identity field (§5.2, name open per Q1) is an
   envelope, `target_id` and `correlation_id` are present, and the stage set is exactly the
   one the smoke actually ran.
5. **No synthetic identity**: no string in the artifact matches `SYNTHETIC_CONTAINER_ID_RE`
   and none is in `FORBIDDEN_SYNTHETIC_CONTAINER_IDS`.

**What R3 must NOT claim.**

R3 does **not** verify the inference stage, and no artifact, report, commit message or PR
description may say that it does. Specifically, R3 does not establish:

* that the `inference` stage's `function_call_id` is worker-observed — no inference call is
  made at all;
* that the `inference` stage's `app_id` or `container_id` resolves against the provider's
  call graph (`call_graph_inputs` → `containers_of_app` → `task_app_id`, §4.1);
* that the smoke artifact is comparable with the published run's `inference` block;
* any end-to-end statement about the inference path.

The reason is structural, not a matter of extra effort: `validate_modal_invocation_provenance`
iterates the stages the artifact *contains* (`for stage_name, stage in stages.items()`,
`evidence_integrity.py:2551`) and requires the three identity fields on each of them. An
artifact without an `inference` stage therefore passes the stage checks **without proving
anything about inference** — and the plan must not let that pass be read as inference
evidence. `MODAL_PROVENANCE_STAGES` (`evidence_integrity.py:1806`) cannot be used to justify
the omission either: it is defined once and referenced nowhere in the repository, so no
validator constrains the stage set.

### 8.2.2 R3b — the inference-plumbing smoke, as a separate authorised step

The `inference` stage cannot be exercised on CPU: it is the stage that calls the model
(`ProductionAuditAgent.generate_solidity_exploit`, the `modal_h100` provider with
`qtum/Qwen3-Coder-30B-A3B-Audit` in the published configuration, §10.1). Proving that the
inference provenance is honest therefore requires an actual inference call.

That call is **not** part of R3 and is **not** authorised by this plan. It is step **R3b**, a
separate and explicitly authorised action with its own gates:

| Aspect | R3 (CPU) | R3b (GPU) |
|---|---|---|
| Stages exercised | `evm_sandbox`, `independent_replay` | `inference` (plus the R3 stages) |
| Cost | CPU containers only | one GPU inference call — Modal credits |
| Authorisation | covered by the run's general authorisation | **separate, explicit authorisation** |
| Proves | the producer/validator plumbing, the envelopes, the evidence references, the EVM fact sourcing | that the inference `function_call_id` is worker-observed, and that the client resolves the provider-issued `app_id` / `container_id` for that call |
| Does **not** prove | anything about inference | the 16-target behaviour |

R3b must run **before** R4, and its result must be recorded, because R4 is a 16-target paid
run: if the inference plumbing is broken, R4 would spend the whole budget to produce 16
artifacts that cannot be published. Making R3b a separately authorised step — rather than a
hidden sub-step of R3 — is what keeps the authorisation boundary honest. This plan spends
nothing and authorises nothing.

### 8.2.3 The run directory of R4 — why it must be new

R4 produces a **new** directory `run_<epoch>_<sha7>/`, and it cannot reuse the published
directory's name. `validate_manifest_git_integrity` (`benchmarks/protocol.py:314`) requires
the run-directory suffix to equal the manifest's `git.commit_sha[:7]`:

```python
if dir_sha_suffix != expected_prefix or len(dir_sha_suffix) < 7:
    return False, f"Run directory suffix '{dir_sha_suffix}' does not match manifest commit prefix '{commit_sha_lower[:7]}'"
```

(`protocol.py:371`.) A regeneration is a **new commit**, so its manifest records a **new**
commit SHA, so its directory must carry the new 7-character prefix. The published run
`run_1794209615_70f5d22/` keeps its name and its bytes because it records the commit
`70f5d22668bb…` it was actually produced from. This is the technical reason behind D9: the
additive layout is not a stylistic preference, it is what the manifest-integrity check
requires.

### 8.2.4 The authoritative run: how it is selected, end to end

D9 says the authoritative run is selected *explicitly*; this section is the mechanism.
Four things have to be true for the selection to be checkable: the validator that reads the
new run must exist, the value that selects the run must be a literal, the run must be bound
to the SHA it was produced from, and the historical validators must keep reading the
historical run.

#### (a) The validator of the replacement iteration

The replacement iteration gets its **own module**. The Iteration 18 validator is **not**
reused for the new run: it resolves its run directory from a module constant
(`DEFAULT_RUN_DIR`) and writes to a fixed report path
(`benchmarks/evidence/iteration18_validation_evidence.json`,
`validate_iteration18_evidence.py:105`), so pointing it at the new run would overwrite the
published Iteration 18 report — the very file D8 declares immutable.

The new module is `benchmarks/validate_iteration24_evidence.py` (named after the iteration
number, which remains the maintainer's choice, **Q6**; the *module* is not). It is a thin
module, not a copy: the Iteration 18 check logic is reused unchanged through
`validate_run_iteration18(*, run_dir, baseline_id, raw_export_path, join_table_path,
code_sha)` (`validate_iteration18_evidence.py:241-256`), which is already parameterised by
`run_dir`. The new module adds exactly two things:

1. `AUTHORITATIVE_RUN_DIR` — the literal path of the new run ((b) below);
2. the check `P0.2.manifest_git_integrity` ((c) below), which **no** iteration validator
   performs today: `validate_manifest_git_integrity` is called from
   `benchmarks/benchmark_runner.py:683` and from the tests only —
   `validate_iteration14_evidence.py` does not mention the reproducibility manifest at all,
   so nothing today ties a published run directory to the SHA in its own manifest.

The CLI of the new module:

```
python -m benchmarks.validate_iteration24_evidence \
  --run-dir benchmarks/artifacts/run_<epoch>_<sha7> \
  --baseline-id baseline_5 \
  --report benchmarks/evidence/iteration24_validation_evidence.json \
  --code-sha <P>
```

#### (b) The exact value that selects the run

Two literals, and only literals:

| Where | Value |
|---|---|
| `AUTHORITATIVE_RUN_DIR` in `validate_iteration24_evidence.py` | `benchmarks/artifacts/run_<epoch>_<sha7>` |
| the `--run-dir` argument of the closure validator's P6.13 command | the same string |

Both are **literal paths**. The authoritative run is never selected by recency, by a glob
over `benchmarks/artifacts/run_*`, by the newest modification time, by the highest epoch, or
by the name of a summary file. A validator reads exactly the directory it was told to read,
and the two literals above are the only two places where the new run is named. The negative
test **T11** pins this: a *newer* run directory in the tree is not selected, because nothing
ever enumerates the tree.

#### (c) How the run is bound to the SHA it was produced from

Two checks — one at production time, one at validation time.

**Production time.** The producer derives the directory name and the manifest's SHA from the
*same* value (`benchmarks/benchmark_runner.py`):

```python
commit_sha = self._get_git_commit_sha()                 # :355 -> git rev-parse HEAD
run_id = f"run_{int(time.time())}_{commit_sha[:7]}"      # :357
...
verify_manifest_git_integrity(                          # :682-685
    repro_manifest, run_artifacts_dir,
    expected_commit_sha=commit_sha, require_clean=effective_require_clean)
```

`validate_manifest_git_integrity` (`benchmarks/protocol.py:353-371`) then asserts three
things: the manifest's SHA is a full 40-character hex SHA; it equals `expected_commit_sha`;
and the run-directory suffix is a **prefix** of that SHA and at least seven characters long —
with the seven-character suffix the producer generates, that is exactly `commit_sha[:7]`. The
published run satisfies this: its manifest records
`git.commit_sha = 70f5d22668bb5ebf72aa9de230fe91790d0e57c8`, and its directory is
`run_1794209615_70f5d22`.

**Validation time.** The new module performs the same check over the bytes on disk, against
the SHA the report is bound to:

```python
manifest = json.loads((run_dir / "reproducibility_manifest.json").read_text(encoding="utf-8"))
ok, error = validate_manifest_git_integrity(
    manifest, run_dir=run_dir, expected_commit_sha=code_sha)
```

`code_sha` is the `--code-sha` value — the commit the run was executed from (§8.2.6). One
check therefore asserts all three bindings at once: the manifest names a full SHA, that SHA
is the SHA the report is bound to, and the directory the artifacts were read from carries
that SHA's first seven characters. A run directory whose suffix does not match its own
manifest cannot pass — and because the literal path is the only way into the directory, a
transcription error in the literal is caught here rather than trusted.

#### (d) The exact P6.13 invocation for the new row

Today P6.13 builds one command shape for every row
(`validate_consolidated_closure_evidence.py:1386-1399`):

```python
command = [sys.executable, "-m", module, "--report", str(report_path)]
if iteration in (16, 17, 18):
    command += ["--rehearsal-dir", str(probe_dir / f"rehearsal{iteration}")]
if expected == "PASSED":
    command += ["--code-sha", bound]
```

The new row needs one argument the historical rows do not have: the run directory. The
change is **additive**, and the historical table is not modified: `HISTORICAL_EVIDENCE`
(`validate_consolidated_closure_evidence.py:196-207`) stays exactly as it is, and a separate
table is added next to it,

```python
#: The replacement evidence: the iteration that supersedes the historical 14-18
#: failure with a new authorised run, the verdict it must reach, the commit it
#: is bound to and the run directory its validator must read. The path is a
#: literal - the authoritative run is never selected by recency.
REPLACEMENT_EVIDENCE: Tuple[Tuple[int, str, str, str], ...] = (
    (24, "PASSED", "<P>", "benchmarks/artifacts/run_<epoch>_<sha7>"),
)
```

and P6.13 iterates over the two tables with one normalised row shape
`(iteration, expected, bound, run_dir)`, where `run_dir` is `None` for every historical row:

```python
rows = [(i, e, b, None) for (i, e, b) in HISTORICAL_EVIDENCE]
rows += list(REPLACEMENT_EVIDENCE)
for iteration, expected, bound, run_dir in rows:
    command = [sys.executable, "-m", module, "--report", str(report_path)]
    if iteration in (16, 17, 18):
        command += ["--rehearsal-dir", str(probe_dir / f"rehearsal{iteration}")]
    if expected == "PASSED":
        command += ["--code-sha", bound]
    if run_dir is not None:
        command += ["--run-dir", run_dir]
```

The concrete invocation for the new row is therefore:

```
python -m benchmarks.validate_iteration24_evidence \
  --report benchmarks/evidence/_closure_probe/iteration24.json \
  --code-sha <P> \
  --run-dir benchmarks/artifacts/run_<epoch>_<sha7>
```

`--baseline-id` keeps its default `baseline_5` — the directory the new run's target
artifacts live in.

**The expected verdict of the new row is `PASSED`, and it is written into
`REPLACEMENT_EVIDENCE` before the run is made — not after its outcome is known.** If the
expectation were written after the run, the check would be unfalsifiable (the closure would
assert whatever the run produced), which is the same defect as the conditional rule D8
forbids. Written in advance, the check has a real failure mode: **if the replacement run does
not pass, the closure fails**, R12 opens a Draft PR that says so, and the historical FAILED
rows stay exactly as they are. The plan does not promise that this row can be satisfied; it
states what it requires.

#### (e) Proof that the historical validators keep using the original run

Four facts, all mechanical:

1. **P6.13 passes no `--run-dir` to them.** The command of the historical rows is built at
   `validate_consolidated_closure_evidence.py:1386-1394` and contains only `--report` (plus
   `--rehearsal-dir` for 16/17/18 and `--code-sha` for the PASSED rows 19–23). The
   `--run-dir` argument is added **only** when the row carries a run directory, and no
   historical row does (`run_dir is None`).
2. **Their default is the published run.** The historical validators resolve their run
   directory from `DEFAULT_RUN_DIR`:
   * `validate_iteration14_evidence.py:66` — `DEFAULT_RUN_DIR = "benchmarks/artifacts/run_1794209615_70f5d22"`
   * `validate_iteration15_evidence.py:75` — the same literal
   * `validate_iteration16_evidence.py:88` — the same literal
   * `validate_iteration17_evidence.py:83` and `validate_iteration18_evidence.py:93` —
     **import** it from the Iteration 16 validator, so they inherit the same literal.

   It is the default of the `--run-dir` argument
   (`validate_iteration14_evidence.py:320`, `…15:405`, `…16:688`, `…17:286`, `…18:328`).
3. **The new path is a different string.**
   `benchmarks/artifacts/run_<epoch>_<sha7>` cannot equal
   `benchmarks/artifacts/run_1794209615_70f5d22` for any epoch and any SHA.
4. **A test pins it.** **T10** asserts that the effective default run directory of each of
   the five historical validators is still `benchmarks/artifacts/run_1794209615_70f5d22`, so
   a future edit that repoints one of them fails the suite instead of silently moving a
   historical validator onto the new run.

The historical run's bytes and the historical verdicts are therefore unaffected: the same
validator reads the same directory and produces the same output — which is what keeps the
14–18 rows of `HISTORICAL_EVIDENCE` matching (§9.4).

### 8.2.5 The compute caps, the stop conditions and the approval boundaries

Three steps of §8.2 start Modal containers, and **all three cost money**. A CPU container on
Modal is compute, not a free local test: it is billed per second, and the GPU step is
billed per second of an H100. Every one of the three steps therefore gets its own hard cap,
its own stop condition and its own explicit approval — fixed **before** the step runs.

#### The caps

| Step | Compute | Hard cap | Timeout / stop condition |
|---|---|---|---|
| **R3** (CPU plumbing smoke) | 1 CPU container, 1 target (`AC-01`), **0** inference calls | **1** container, **1** target, `--hypotheses=1`, **≤ 2** attempts, a wall-clock budget of **20 minutes** per attempt | the per-call timeout stays at the published value (`timeout_sec = 120`, §10.1); the client aborts the attempt at the 20-minute budget, stops the app (`modal app stop`) and records the failure; a second failed attempt ends the step |
| **R3b** (inference-plumbing smoke) | 1 GPU container (`modal_h100`), 1 target, **exactly 1** inference call | **1** GPU call, `--hypotheses=1`, **≤ 2** attempts, a wall-clock budget of **20 minutes** per attempt | the same abort rule; a failed R3b **ends the sequence** — R4 does not start (§8.3) |
| **R4** (the 16-target run) | 16 targets × H100, the published configuration | the monetary ceiling of **Q5** (§10.3) — no per-call cost may exceed it | the per-call timeout stays at `timeout_sec = 120` per target; the operator stops the app when the accumulated spend reaches the ceiling; the partial result and its billing window are published, and the run is **not** retried silently |

Two invariants apply to all three steps:

* **A cap is a stop condition, not a target.** The step stops when the cap is reached; it
  never continues because the result is "almost" there.
* **The attempt counter is part of the cap.** "≤ 2 attempts" means two invocations of the
  step in total. A retry is a new invocation, it is counted, and it needs an approval of its
  own (below).

The monetary ceilings of R3, R3b and R4 are **three separate numbers**, each attached to the
approval of the respective step. **Q5** (§11.2) is the ceiling of the paid steps (R3b and
R4); the CPU step R3 has its own, smaller ceiling — because it is a separate authorisation,
not a free preliminary.

#### The approval boundaries

| Approval | Covers | Does **not** cover |
|---|---|---|
| **A-R3** | R3 only: the CPU container, one target, one hypothesis, the CPU ceiling | R3b (GPU), R4 (16 targets, H100) |
| **A-R3b** | R3b only: one GPU inference call for one target, the GPU ceiling | R3, R4 |
| **A-R4** | R4 only: the 16-target H100 run, the Q5 ceiling | R3, R3b, and any retry of either |

The rules:

1. **Approval for R4 does not approve R3 or R3b, and approval for R3 does not approve R3b.**
   Each step is authorised separately, in writing, with its own ceiling attached.
2. **Approval for R3b does not approve R4.** R3b exists to prove the inference plumbing
   *before* the expensive run; if it fails, the sequence stops at R3b (§8.3) and R4 needs a
   **new** approval, not the old one.
3. **The attempt counter is part of the approval.** The approval of a step covers at most the
   number of attempts its cap states; a further attempt is a new invocation and needs a new
   approval for that step.
4. **The approval record is part of the PR.** The PR of the regeneration iteration records,
   per step: the approver, the date, the approved ceiling and the actual spend. A step
   without that record did not run.
5. **This plan approves nothing.** It specifies the caps and the boundaries; no approval is
   given here, no container was started, and no credits were spent while producing it.

### 8.2.6 The commit the run executes: binding the capture SHA to the code

The manifest's `git.commit_sha` is not a field an operator fills in. The producer reads it
from the checkout that executes the run (`benchmarks/benchmark_runner.py:180-186`):

```python
def _get_git_commit_sha(self) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True, cwd=str(self.dataset_path.parent)
    ).strip()
```

and the same value names the run directory
(`run_id = f"run_{int(time.time())}_{commit_sha[:7]}"`, `:357`) and goes into the manifest's
`git` block (`:188-202`, `GitManifest(commit_sha=…, is_dirty=…, branch=…)`). The manifest
therefore **cannot** claim a SHA other than the code that actually executed — but only as
long as the *intended* checkout is the one that runs. The risk is not a lying manifest; it is
running from the wrong checkout.

The chain R1 → R2 → R3/R3b → R4 advances HEAD: R2 adds the negative tests, R3 and R3b are
run steps whose transcripts land on the branch, and R4's run directory is named after the SHA
that happened to be checked out at that moment. If the run were executed from the branch head
of that moment, the manifest would record the *tests* commit — a SHA that is not the commit
the producer was written in, and not the commit the closure's producer-immutability check
(P6.14) is about.

**The contract: the run executes from a detached worktree pinned at the producer commit.**

1. **R1 produces the producer commit `P`.** `P` is the last commit that touches
   `modal_app.py`, `adapters.py`, `benchmark_runner.py` or the validators. No commit after
   `P` may touch any of them — that is what makes P6.14's diff empty (§9.3).
2. **R3, R3b and R4 are executed from a detached worktree at `P`:**

   ```bash
   git -c core.autocrlf=false worktree add --detach ../run-worktree <P>
   cd ../run-worktree
   ```

   The branch may advance meanwhile (tests, documents, the published reports); the worktree
   does not move. `git rev-parse HEAD` inside it returns `P` — which is exactly the SHA the
   manifest records, because the producer resolves it with the cwd of the dataset directory
   (`benchmarks/`, inside that worktree).
3. **The worktree is clean.** `git status --porcelain` must be empty, so the manifest's
   `git.is_dirty` is `false`. The producer enforces this for a real run anyway
   (`effective_require_clean`, `benchmarks/benchmark_runner.py:676-681`), and the run must
   not be started with `AEGIS_ALLOW_DIRTY=1`.
4. **What the manifest records.** `git.commit_sha = P` (the full 40 characters),
   `git.is_dirty = false`, `git.branch = "HEAD"` — the last one because
   `git rev-parse --abbrev-ref HEAD` returns `HEAD` in a detached worktree. The published
   run, by contrast, recorded `git.branch = "feat/empirical-benchmark-runner"`, because it
   was made from a branch checkout. The new value is the visible trace of the detached
   worktree — not a defect.
5. **The run directory follows from the same SHA.** The directory is `run_<epoch>_<P[:7]>/`;
   `P[:7]` is the manifest's `git.commit_sha[:7]`, and
   `validate_manifest_git_integrity` re-checks the directory name against it
   (`benchmarks/protocol.py:365-371`).
6. **The report is bound to `P`.** The replacement report (R9) and the closure's probe report
   (P6.13) are both produced with `--code-sha <P>`, so the report's `code_sha` is the SHA the
   run was executed from.
7. **The closure's producer-immutability check binds to the same source.** P6.14's
   `capture_sha` for the replacement capture is `P`, and the diff it computes is
   `git diff --name-only <P> <closure commit> -- <the producer paths>` — empty, because no
   commit after `P` touches them (§9.3).

**The manifest must never claim a SHA other than the code that actually executed.** That is
why the plan does not "fix up" the SHA afterwards, and why the worktree is detached: a
detached worktree at `P` is the only arrangement in which the manifest's SHA, the
directory's suffix, the report's `code_sha` and the closure's capture binding are the same
value *by construction* rather than by coincidence.

If a later step (a test, a document, a published report) advances the branch, **nothing
about the run changes**: the run stays bound to `P`, and the closure is bound to the closure
commit. The two are related by ancestry — `P` is an ancestor of the closure commit — which is
exactly what P6.14 asserts.

### 8.3 Ordering rationale

The order is a strict dependency chain:

```
R3 (CPU smoke) ──> R3b (GPU inference smoke, separately authorised) ──> R4 (run)
                                                                            │
                                                                            v
                                              R5 (verify new bytes) ──> R6 (publish run tree additively)
                                                                            │
              ┌─────────────────────────────────────────────────────────────┤
              v                             v                               v
        R7 (harness)              R9 (new run report)                R6 artifacts
              │                             │
              v                             │
        R8 (join table)                    │
              │                             │
              └─────────────┬───────────────┘
                            v
              R10 (iter 19-23 + closure) ──> R11 (full suite) ──> R12 (PR)
```

R5 sits **before** R6 on purpose: the new bytes are verified while they are still outside
the published tree, so a bad run never becomes published evidence.

R3b sits **before** R4 on purpose: the inference plumbing is the one part of the provenance
contract that R3 cannot exercise, and R4 is the expensive step. Paying for 16 GPU targets
before the inference path is known to work would spend the entire budget to produce
unpublishable artifacts.

**A failed smoke ends the sequence.** A smoke that fails its gate stops the regeneration
there (§8.2.5): the sequence does not continue into R4 with a producer that is known to be
broken, and R4 requires its own approval in any case.

**All three execution steps run in the same detached worktree** at the producer commit `P`
(§8.2.6), so the smoke and the run are produced from exactly the code the closure will
later bind to. The worktree holds no published bytes — it is removed with
`git worktree remove --force` once the run's bytes have been published (§8.4).

R9 no longer regenerates the Iterations 14–18 reports: those are immutable (D8). It produces
the **new** run's own iteration report instead, so the FAILED history and the replacement
evidence are two separate files, not one rewritten file.

### 8.4 Rollback

**A rollback must never rewrite published history.** `git reset --hard` on a pushed branch
destroys commits the branch already advertises: it forces a force-push, it invalidates
everyone who has fetched the branch, and it erases the record of what was actually tried.
The published evidence in this repository is a *history of verdicts*, so its history must be
additive too.

Every step is a separate commit on the regeneration branch. Rollback is therefore:

```bash
# 1. ordinary revert commits — the branch history is preserved
git revert --no-commit <sha-of-the-step-to-undo>
git commit -m "revert: undo step R<n> (<what it published>)"

# 2. or, if several steps must go, a dedicated rollback branch
git switch -c rollback/r<n>-<short-desc> <last-good-step-sha>
git cherry-pick <the commits that must survive>
```

Both forms are **non-destructive**: no force-push, no history rewrite, no lost commit. The
revert commits stay in the branch and show up in the PR exactly what was undone and why.

`git reset --hard` is permitted in exactly one place: a **local, disposable worktree** whose
commits were never pushed — for example the throwaway smoke tree of R3 / R3b, or a scratch
clone used to re-run a validator against an older revision. Such a worktree is discarded as
a whole (`git worktree remove --force <path>`); nothing it contains was ever published, so
nothing can be lost. The **detached run worktree** at `P` (§8.2.6) is exactly such a
worktree: it holds the executed code and the not-yet-published run output, and it is
discarded as a whole once the run's bytes have been published.

If R4 produced a live run that must be discarded, the Modal-side cleanup (stopping the app,
deleting the run's artefacts, re-exporting the billing window if a new one was opened) is a
separate operational action, listed in the PR description; it does not touch the published
tree.

Because the published tree is only touched from R6 onwards, reverting R6 and everything after
it restores the published evidence byte-for-byte, while the commits that introduced the
change stay visible in the history. The published evidence before R6 is additionally
recoverable from the base commit `a8a8857` — every published file is tracked, so
`git show a8a8857:<path>` always yields the original bytes.

**Rollback triggers:** any validator verdict other than the expected one; any `modal-app://`
or synthetic container id in the new bytes; a cost overrun; a stage whose facts are neither
observed nor explicitly `NOT_AVAILABLE`.

---

## 9. Preservation of the historical evidence

### 9.1 What must not change

The task requires: *"explicitly preserve the historical Iterations 14–18 FAILED (0/16)
result unless a genuinely new authorised empirical run produces replacement evidence. Never
rewrite history to make it green."*

The current published state is:

```
iteration14  FAILED (0/16)   bound to 43436b02…
iteration15  FAILED (0/16)   bound to cf262236…
iteration16  FAILED (0/16)   bound to b1946536…
iteration17  FAILED (0/16)   bound to e9faff40…
iteration18  FAILED (0/16)   bound to 8813cebd…
iteration19  PASSED (12/12)  bound to 18ad9740…
iteration20  PASSED (12/12)  bound to 64392a7b…
iteration21  PASSED (13/13)  bound to 40c06309…
iteration22  PASSED (11/11)  bound to f0ce026d…
iteration23  PASSED (12/12)  bound to 749cba24…
closure      PASSED (21/21)  bound to 690f39a1…
```

### 9.2 The policy: one rule, no conditional branch

**The published Iterations 14–18 `FAILED (0/16)` reports are immutable.** They are the
historical record of the defect this plan exists to fix, and they stay byte-for-byte as they
are published. A regeneration never edits them, never "refreshes" them, and never turns them
green.

This is decision **D8** (§11.1). It is a single rule without a conditional branch, and that is
deliberate. The earlier draft of this plan offered a conditional — "keep FAILED until a new run
passes, then regenerate the reports against the new run" — and a conditional is precisely how
history gets rewritten: the condition is evaluated by the same person who wants the green
result, and the old verdict is then replaced by a new file at the same path.

**What happens instead.** A new authorised run produces **new-run / replacement evidence**,
published under its own identity:

| | Historical evidence | Replacement evidence |
|---|---|---|
| Published files | `iteration14..18_validation_evidence.json` (5 files) | the new iteration's own report file(s) |
| Verdicts | `FAILED (0/16)` — unchanged | whatever the validators output against the new run |
| Artifacts | `run_1794209615_70f5d22/` — unchanged, in place | the new `run_<epoch>_<sha7>/` (D9) |
| Role in the closure | rows 14–18 of `HISTORICAL_EVIDENCE`, expected string `FAILED (0/16 targets)` | a **new row** in `HISTORICAL_EVIDENCE`, expected string = the new run's verdict |

The closure therefore refers to **both**: the 14–18 rows keep asserting that the historical
verdicts are still exactly `FAILED (0/16 targets)`, and a new row asserts the verdict of the
replacement run. The closure report states both in the same artefact, so a reader sees the
failure and its replacement side by side — with the failure still there.

**The name matters.** The replacement is *not* "Iteration 14 regenerated", and it is not
"Iterations 14–18 now passing". It is a **new iteration** — its number is a maintainer choice
(open question **Q6**, §11.2) — whose report records the new run's own verdicts. The numbers
14–18 continue to denote the run that produced the FAILED verdicts, which is exactly what
makes those verdicts meaningful.

**No report is hand-edited, in either direction.** Every published verdict is the output of a
validator run against bytes on disk: the historical one was produced by the validator against
the old artifacts and is preserved as-is; the replacement one is produced by the validator
against the new artifacts. Neither is typed by hand. That is what makes "never rewrite
history" enforceable rather than aspirational.

**What is *not* claimed.** The replacement run does not retroactively make the old run valid.
Iterations 14–18 continue to fail, and that failure continues to be the truthful statement
about the artifacts they were computed from. If the replacement run also fails, the outcome is
simply two failures — a legitimate result of an authorised experiment.

### 9.3 The producer-source immutability check (P6.14)

The closure validator asserts that the producer source is byte-wise unchanged between the
capture commit `40c063093c8d773d20f828fb290c68b5790a7cc5` and the reported commit:

```python
capture_sha = "40c063093c8d773d20f828fb290c68b5790a7cc5"
elif not _is_ancestor(capture_sha, code_sha): ...
diff = _git("diff", "--name-only", capture_sha, code_sha, "--", "modal_app.py")
if producer_changed:
    producer_errors.append("the producer source changed between the commit the capture was made from ...")
```

**What the check actually covers today.** Two limits, both measured:

* the diff is computed over **one** path — `modal_app.py` — while the producer of the §5
  schema spans three files (`modal_app.py`, `adapters.py`, `benchmark_runner.py`);
* it is anchored to **one** capture commit — the Iteration 21 capture.

At the baseline commit both limits are harmless: `git diff --name-only 40c06309… <branch
head> -- modal_app.py` and the same diff over the three producer paths are both empty, and
`40c06309…` is an ancestor of the branch head. The check passes today because the producer
has not changed since that capture.

**Consequence for the plan.** R1 *does* change the producer — that is its purpose — so the
capture of the replacement run is made from the **changed** producer. The capture SHA of the
replacement evidence is therefore the R1 producer commit `P` (§8.2.6), not `40c06309…`.

**How the check binds to the same executed source.** The single constant becomes a table of
capture bindings, one per capture, and the historical entry stays exactly as it is:

```python
#: The commit each capture was made from, and the producer paths whose
#: immutability that capture depends on.
CAPTURE_BINDINGS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    # the capture of Iteration 21 - unchanged: same commit, same single path
    ("40c063093c8d773d20f828fb290c68b5790a7cc5", ("modal_app.py",)),
    # the capture of the replacement run: the producer commit P, and every
    # producer path the run depends on
    ("<P>", ("modal_app.py", "adapters.py", "benchmark_runner.py")),
)
```

P6.14 then checks, for each binding, that the capture is an ancestor of the reported commit
and that `git diff --name-only <capture> <reported commit> -- <the producer paths of that
binding>` is empty.

**The Iteration 21 binding must not be extended** to the two other producer paths: R1
changes them, so extending the list would make the *historical* check fail over a change
that does not affect the Iteration 21 capture at all. The historical check keeps its exact
meaning — one commit, one path — and the replacement binding adds the two files the
replacement run actually depends on.

**`P` is not a value that may be chosen after the fact.** It is the commit the run was
executed from (§8.2.6), and it is the same value that the manifest's `git.commit_sha`
carries, that the run directory's suffix is derived from, and that the replacement report
is bound to. The closure's check therefore compares the *executed* source against the
*reported* source, not a hand-copied constant: had the run been executed from a different
checkout, the manifest's SHA, the directory's suffix and the closure's capture binding
would disagree — and the manifest-integrity check of §8.2.4 (c) would fail before P6.14 is
reached at all.

### 9.4 The historical-evidence check (P6.13)

P6.13 executes the validators of Iterations 14–23 and asserts their **output strings**:

```python
for iteration, expected, bound in HISTORICAL_EVIDENCE:
    ...
    if not any(expected in line for line in output):
        history_errors.append(
            f"the validator of Iteration {iteration} does not report {expected!r} in its output"
        )
```

`HISTORICAL_EVIDENCE` (`benchmarks/validate_consolidated_closure_evidence.py:196`, consumed
at line 1379) therefore encodes, per iteration, the expected verdict string and the expected
`code_sha` binding.

Under D8 the table changes in exactly one way: a **row is added** for the replacement
iteration. The rows for Iterations 14–18 are **not** touched — neither their expected verdict
string (`FAILED (0/16 targets)`) nor their bound `code_sha`. And because the bytes of the old
run directory are left alone as well (§7.4 row 17), those validators keep producing the same
output, so the old rows keep matching.

| Row in `HISTORICAL_EVIDENCE` | Before | After |
|---|---|---|
| 14 … 18 | `FAILED (0/16 targets)`, bound to `43436b02…` … `8813cebd…` | **unchanged** |
| 19 … 23 | `PASSED`, bound to their SHAs | unchanged, unless their own capture is redone |
| closure | `21/21 PASSED` | `21/21 PASSED`, plus the replacement row |

The coupling P6.13 creates is therefore *additive*: the new row adds a requirement, and it
cannot alter the meaning of the rows above it. Its three values are fixed **before** the run,
not fitted to its outcome:

| Value of the new row | Fixed when | Value |
|---|---|---|
| the expected verdict | at R1, before any run | `PASSED` |
| the bound `code_sha` | at R1, before any run | `P` — the producer commit the run executes from (§8.2.6) |
| the run directory | the SHA part at R1 (`P[:7]`); the epoch part by the run itself (`benchmark_runner.py:357`) | `benchmarks/artifacts/run_<epoch>_<P[:7]>` — a literal, transcribed into the new module and into `REPLACEMENT_EVIDENCE` when the run directory exists, and **verified** against the manifest by the check of §8.2.4 (c), so a wrong transcription cannot pass |

Writing the expectation *after* the run would make the check unfalsifiable — the closure
would assert whatever the run produced, which is the same defect as the conditional rule D8
forbids. Written in advance, the check has a real failure mode: **if the replacement run
does not pass, the closure fails**, R12 opens a Draft PR that reports the failure, and the
historical FAILED rows stay exactly as they are. The plan does not promise that the new row
can be satisfied; it states what it requires.

The earlier draft of this plan called this coupling "the single most dangerous coupling in
the whole plan", because it assumed the 14–18 rows would have to be **edited** from `FAILED`
to `PASSED`. Under D8 they are never edited; the risk that remains is the mechanical one —
adding a row whose expected string does not match the validator's actual output — and P6.13
catches precisely that. The exact command of the new row is specified in §8.2.4 (d).

---

## 10. The future Modal invocation and capture procedure

**This section is a specification for a future, separately authorised run. Nothing in it was
executed.** No Modal call, no deployment, no GPU allocation, no paid compute, no Modal
credits were spent while producing this plan.

### 10.1 Command shape

The published artifacts record the exact invocation of the original run:

```
modal run modal_app.py --target-name AccessControlVault --hypotheses=3 \
  --provider=modal_h100 --model=qtum/Qwen3-Coder-30B-A3B-Audit
```

with `timeout_sec = 120`, `resource_budget.max_hypotheses = 3`, and an allowlist of the 16
targets. The regeneration should use the **same** configuration, so the only variable is the
provenance schema. A different configuration would change the benchmark's meaning and turn
a provenance migration into a benchmark re-run.

### 10.2 The capture sequence

1. **Pre-flight (no cost):** confirm the app exists and the model is available; confirm the
   worker image contains `forge`; confirm the client can reach the provider's container
   listing (`ModalProvider.containers_of_app`).
2. **CPU plumbing smoke (no GPU cost):** one target, `--provider=modal_cpu`, exercising the
   `evm_sandbox` and `independent_replay` stages only — this is **R3** (§8.2.1). Assert the §5
   contract for the stages it actually ran, before any paid run. A CPU container is still
   Modal compute and still costs money, so R3 has its own ceiling and its own approval
   **A-R3** (§8.2.5).
3. **Inference-plumbing smoke (minimal GPU cost):** one target with the published inference
   configuration, exercising the `inference` stage and resolving its provider-issued identities
   — this is **R3b** (§8.2.2), and it needs its **own explicit authorisation** **A-R3b** with
   its cap fixed before the first call (§8.2.5).
4. **Full run (cost):** the 16 targets, `modal_h100`, `--hypotheses=3`, executed from the
   detached worktree at `P` (§8.2.6) under the approval **A-R4** and the ceiling of Q5.
5. **Client-side correlation:** for every stage, resolve the provider-issued
   `container_id` from the `function_call_id` the worker observed, using
   `call_graph_inputs` → `containers_of_app` → `task_app_id`, with the last one as an
   independent cross-check. If the provider does not answer, the field is recorded
   `NOT_AVAILABLE` with the provider's own reason — **never** a synthetic id (§6.6 T5).
6. **Billing export:** export the raw billing line items for the run's window
   (`modal app billing` / the workspace's billing export) into
   `modal_billing_report_raw.json`. **Only if a new billing window is opened** — otherwise the
   raw export, and its digest in the join table, stay exactly as they are (§4.4, §7.3).
7. **Join table:** regenerate schema 3.0.0 from the raw export; target-level costs stay
   `null` unless an exact, unique provider join exists.

### 10.3 Cost controls

| Control | Value |
|---|---|
| Per-step ceilings | **three separate numbers** — the CPU ceiling of R3, the GPU ceiling of R3b, and the ceiling of R4 (§8.2.5). The two paid ceilings (R3b and R4) are **not yet set** — open question **Q5** (§11.2) |
| Per-step approvals | **A-R3**, **A-R3b**, **A-R4** — one per step, each with its own ceiling (§8.2.5). No approval implies another: the approval of R4 approves R4 and nothing else |
| Per-step caps | 1 container / 1 target / ≤ 2 attempts for the smokes, 1 GPU call for R3b; the 16-target run is bounded by the Q5 ceiling (§8.2.5) |
| Target cost attribution | `null` + `UNATTRIBUTED_NO_INVOCATION_LEVEL_JOIN` unless a proven join exists — the existing policy already prevents a target cost from being invented |
| Aggregate allocation | `FORBIDDEN` (`attribution_policy.aggregate_bucket_allocation`) — no aggregate bucket may be spread over targets |
| App-session granularity | the app-session total is the only cost that may be published |
| Pre-flight | the smoke run in step 2 happens **before** the 16-target run and must be reviewed; a failed smoke ends the sequence (§8.3) |
| GPU | `H100` only where the original run used it; `CPU` for the EVM-sandbox and replay stages |
| Executed code | the run is executed from the detached worktree at `P` (§8.2.6) — the manifest, the run directory, the report and the closure carry that one SHA |

### 10.4 The billing join fields

`PROVIDER_JOIN_FIELDS = ("invocation_id", "function_call_id", "task_id")`. The regeneration
is the first opportunity to actually populate a target-level join: the worker now observes a
real `function_call_id`, and the client resolves the provider's `task_id` (the container id)
for it. If the provider's billing line items carry a matching correlation key, the join
resolves to exactly one raw line item and a target-level cost becomes publishable. If it
does not, the join stays `null` — the honest state.

---

## 11. Design decisions and unresolved questions

### 11.1 Decisions taken in this plan

Every decision has its own ID, and an ID is used for exactly one decision. A decision is
something this plan settles; anything that is still the maintainer's call is a question in
§11.2 and is **not** listed here.

| # | Decision | Rationale |
|---|---|---|
| **D1** | The regeneration is a **schema migration**, not a value cleanup. | The published schema is rejected as a whole (F2); a URI-only edit would leave `app_id`/`function_call_id`/`container_id` and the flat EVM facts still invalid. |
| **D2** | The upstream bytes are **not** adopted; they are used as a field-level reference only, and their three defects (§3.2) are fixed. | Upstream's bytes fail the iteration-line validators and add a synthetic container id (F3). |
| **D3** | The iteration-line `observed()` / `not_available()` envelope is the target contract; upstream's flat `"NOT_AVAILABLE"` strings are **not**. The *name* of the run-level identity field is **not** decided here (Q1) — only its envelope is. | The envelope carries a reason, an absence kind, an observation side and a digest-checked evidence reference — the Iteration 15/16/20 rules. Flat strings satisfy none of them. |
| **D4** | The producer's `capture_modal_runtime_identity` is reused as-is for the worker side; the client side uses `ModalProvider` (already implemented, currently unwired). | Both are already in the tree and already honest. The plan wires them; it does not reinvent them. |
| **D5** | `image_digest` is `NOT_AVAILABLE` with a reason unless the provider issues the image id client-side. | The container sandbox exposes no OCI manifest digest; a digest cannot be derived from a tag. |
| **D6** | The `legacy_key` inline check stays; `has_synthetic_modal_uri` is additionally promoted to a **verdict** on the artifact, manifest, summary and join-table paths. | §6.5 C1–C3; the detector exists but is not enforced (F4). |
| **D7** | No published verdict is hand-edited; every published report is the output of a validator run against bytes on disk. | §9.2. |
| **D8** | **The historical evidence is immutable.** The published Iterations 14–18 `FAILED (0/16)` reports, and the run directory they were computed from, stay byte-for-byte. A new authorised run is published as **new-run / replacement evidence** under a new iteration number, and the closure refers to both the old history and the new result. | "Never rewrite history" is enforceable only if the old verdict is never rewritten. A conditional rule ("keep FAILED *until* a new run passes") is how history gets rewritten, because the condition is evaluated by the party that wants the green result. §9.2, §9.4. |
| **D9** | **The run tree is additive.** The new run lives in a **new** `run_<epoch>_<sha7>/` directory; the published run directory is not replaced, moved or deleted. The authoritative run is selected **explicitly**, never by "the newest directory in the tree". | The manifest-integrity check forces a new directory name (§8.2.3), and the additive layout keeps the old bytes — and the old verdicts — reachable and explicitly marked as historical (§7.4 row 17). |
| **D10** | **One digest convention.** Every digest the regenerated evidence publishes is computed over the **git blob bytes** (LF); the manifest's 15 CRLF-based stdout digests are re-pinned so the manifest and the harness validation agree. | The two published files currently disagree on 15 of the 32 stdout digests (§7.3). Publishing a third convention would preserve the contradiction instead of ending it. |
| **D11** | **Rollback is non-destructive.** A pushed branch is rolled back with `git revert` commits or a dedicated rollback branch; `git reset --hard` is confined to a local, unpublished, disposable worktree. | A force-push on the evidence branch would destroy the record of what was tried — the same failure mode as rewriting a verdict. §8.4. |
| **D12** | **The root-level `latest_summary.json` stays a byte-identical mirror of the authoritative run's `summary.json`.** The pointer alternative is not part of this plan. | The mirror is checkable (a byte comparison), and the superseded content is not lost: it stays in the historical run's own `summary.json` (§7.4 row 4). This closes **Q4**, which is withdrawn from §11.2. |
| **D13** | **The authoritative run is selected by a literal path, through the replacement iteration's own validator module.** The new module is `benchmarks/validate_iteration24_evidence.py`; it reuses the Iteration 18 check logic unchanged and adds the manifest-integrity check that no iteration validator performs today. The closure selects the run through an explicit `--run-dir` argument. | D9 states the principle — explicit selection, never by recency — and this is its concrete form: the value is a literal in exactly two places, and the run is bound to the SHA in its own manifest (§8.2.4). The Iteration 18 validator cannot be reused: it writes to a fixed report path and would overwrite the published Iteration 18 report (D8). |
| **D14** | **Every compute step has its own hard cap, its own stop condition and its own explicit approval.** No approval implies another. | A CPU container on Modal is compute, too, and R3b spends GPU credits before the Q5 ceiling is set. A cap that is not fixed before the step starts is not a cap (§8.2.5). |
| **D15** | **The run executes from a detached worktree pinned at the producer commit `P`.** The manifest's `git.commit_sha`, the run directory's suffix, the report's `code_sha` and the closure's capture binding are therefore the same value by construction. | The manifest reads its SHA from the checkout that executes the run, so the risk is not a lying manifest but running from the wrong checkout. A detached worktree is the only arrangement in which the four bindings cannot drift apart (§8.2.6, §9.3). |

### 11.2 Unresolved questions for the maintainer

These are **not** decided by this plan. Three questions of the earlier draft — whether
Iterations 14–18 may turn green, whether the new run replaces or joins the published run
tree, and whether `latest_summary.json` stays a mirror or becomes a pointer — are no longer
open: they are settled by **D8**, **D9** and **D12** respectively. **Q4 is withdrawn**
(absorbed into D12); the remaining questions keep their IDs, and an ID is never reused, so
every reference to a question elsewhere in this document stays valid.

| # | Question | Why it blocks | Options |
|---|---|---|---|
| **Q1** | What should the run-level identity field be called — `modal_app_id`, `app_session_id` or `app_id`? | It changes the published field name in the new artifacts + manifest + summaries. The semantics and the envelope are already fixed (§5.3, D3); only the spelling is open. | (a) `app_session_id` — upstream's spelling, slightly imprecise; (b) keep `modal_app_id`; (c) `app_id` — the accurate name, since the value is the app id and not a session |
| **Q2** | Are upstream's *other* field removals (`stages.*.resource_interval`, `stages.*.billing_line_item`) in scope as well? | The upstream removed those fields; the iteration line's validator expects per-stage `app_id`/`function_call_id`/`container_id`, and the join table carries the billing detail | (a) keep the iteration-line field set; (b) adopt upstream's set and relax the validator |
| **Q3** | Is `remote_os` allowed to keep its coincident legacy value? | `EVM_FACTS_WITH_COINCIDENT_LEGACY_VALUE` already permits it **when the source proves it**; the plan makes the source real. If the worker's real `/etc/os-release` says something else, the value changes and the pin changes | (a) accept whatever the worker observes; (b) require an exact value match as a gate |
| **Q5** | What are the monetary ceilings of the paid steps — the GPU smoke R3b and the 16-target run R4? | §10.3, §8.2.5. R3b spends GPU credits *before* R4, so its own ceiling must exist before its approval **A-R3b** is granted; R4's ceiling must exist before **A-R4**. (The CPU smoke R3 has its own, smaller ceiling, set in its approval **A-R3**.) | to be set by the maintainer |
| **Q6** | Under which iteration number is the replacement run published? | The closure's `REPLACEMENT_EVIDENCE` needs a row for it (§9.4), and the new validator module is named after the number (§8.2.4 a). The *module* is already decided — a new module, not a reuse of the Iteration 18 validator (D13) | (a) Iteration 24; (b) Iteration 25; (c) a different number |
| **Q7** | How is the superseded run marked, so that "no `modal-app://` in the published evidence" stays checkable without touching the historical bytes? | The old run keeps its 66 pseudo-URIs (D8, D9); the answer decides whether the invariant is checked per run or globally | (a) mark it only *outside* the artifacts (change-impact matrix + closure report) and scope the invariant to the authoritative run — this is the plan's default; (b) add a `superseded_by` marker inside the old run's JSON — that changes historical bytes and therefore conflicts with D8 |

### 11.3 Acceptance criteria for the implementation (future iteration)

The regeneration is acceptable only when **all** of the following hold:

1. `has_synthetic_modal_uri` is `False` for every JSON file of the **authoritative run** and
   of the root-level `latest_summary.json` — verified by the §2 script, whose output is
   committed with the diff. The historical run is reported separately and keeps its 66
   occurrences (D8, D9).
2. No string in any artifact of the authoritative run matches `SYNTHETIC_CONTAINER_ID_RE`.
3. Every artifact of the authoritative run passes `validate_modal_invocation_provenance`
   **and** `validate_remote_evm_toolchain_provenance`.
4. Every remote-EVM fact is either an `observed` envelope with a source matching
   `EVM_FACT_REQUIRED_SOURCE_TOKENS`, or a `not_available` envelope with a reason, an
   absence kind and — where the provider should have answered — a digest-valid
   `evidence_ref`.
5. No value in the new artifacts was copied from the old artifacts or from upstream's
   bytes. The run directory is new; its bytes come from a new run.
6. The negative tests T1–T9 exist, and each was observed to fail against the pre-fix code.
7. `python -m benchmarks.regenerate_billing_join_table --check` → PASSED; the join table is
   still schema 3.0.0 with `aggregate_bucket_allocation: "FORBIDDEN"`; **all 17 harness
   digests match the regenerated harness validation file**; and `source_raw_export.sha256` is
   still `1529b1b9…` unless the raw export was re-exported (§4.4, §7.3).
8. Every validator exits 0 and reports its expected verdict:
   iterations 14–18 → **`FAILED (0/16)`, unchanged** (D8);
   the replacement iteration → the verdict the new run actually produced (D8);
   iterations 19–23 → `PASSED`; closure → `21/21 PASSED`, with the 14–18 rows of
   `HISTORICAL_EVIDENCE` unchanged and the replacement row added.
9. `pytest -q` is green, with no test weakened, relaxed or skipped. The seven live-provider
   skips (Foundry not on `PATH`, Slither not installed) remain skips and are run only by
   the `foundry-integration` CI job on the Linux runner.
10. `git diff --stat` shows only the files listed in §7.4, and the diff contains no
    hand-edited verdict. The published run directory `run_1794209615_70f5d22/` and the five
    `iteration14..18_validation_evidence.json` reports **do not appear in the diff at all**
    (D8, D9).
11. Every digest published by the regenerated evidence is computed over the git blob bytes,
    and the manifest's and the harness validation's digests for the same 32 stdout/stderr
    files **agree** (D10).
12. The rollback path is revert-based: the branch contains no force-push, and reverting R6
    and everything after it restores the published bytes exactly (D11).
13. The authoritative run is selected by a **literal path** only. The effective `--run-dir`
    default of each historical validator (14–18) is still
    `benchmarks/artifacts/run_1794209615_70f5d22` (**T10**), and no code path selects a run
    directory by recency, by a glob or by a summary filename (**T11**) — D13, §8.2.4 (b, e).
14. The new run's `reproducibility_manifest.json` passes
    `validate_manifest_git_integrity` against the run directory **and** against the SHA the
    report is bound to; the directory's suffix equals the manifest's `git.commit_sha[:7]`
    (§8.2.4 c).
15. The manifest's `git.commit_sha` is the commit the run was executed from; the replacement
    report's `code_sha` is that commit; the closure's capture binding for the replacement is
    that commit; and
    `git diff --name-only <that commit> <closure commit> -- modal_app.py adapters.py benchmark_runner.py`
    is empty. The Iteration 21 binding of P6.14 is unchanged — same commit, same single path
    (D15, §9.3).
16. `latest_summary.json` is byte-identical to the authoritative run's `summary.json`, and the
    historical run's own `summary.json` is byte-identical to what it was before (D12).
17. Every compute step has a recorded approval, a recorded ceiling and a recorded actual
    spend, no step exceeded its cap, and the approval of one step is not used for another
    (D14, §8.2.5).

---

## 12. What was deliberately not done

* No code implementation. The schema of §5, the call-path changes of §6.5 and the tests of
  §6.6 are **specified**, not written.
* No published evidence artifact was regenerated, renamed, rewritten or re-pinned.
* No validator, schema, test, manifest, billing table or historical report was changed.
* No live Modal invocation, no deployment, no redeployment, no H100/T4 allocation, no
  Foundry remote run, no paid computation. No Modal credits were spent.
* No compute step was authorised: the approvals **A-R3**, **A-R3b** and **A-R4** of §8.2.5 are
  specified here, and none of them was granted. The caps and the ceilings of §8.2.5 are a
  specification, not a budget that was spent.
* No run was executed from the detached worktree at `P` (§8.2.6): the producer commit `P` does
  not exist yet — it is created by R1 of a future, separately authorised iteration.
* No published digest was re-computed into a record.
* The historical FAILED (0/16) results of Iterations 14–18 were not rewritten, and the run
  directory they were computed from was not modified, moved or deleted (D8, D9).
* PR #12 and PR #13 were not merged, re-based, closed or modified; their base branches and
  `main` were not touched.
* No branch was force-pushed and no published branch had its history rewritten (D11).
* The only file changed by this iteration is this document — no code, no evidence, no
  validator, no schema, no report.
