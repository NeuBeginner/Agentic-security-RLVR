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
| **C6** | Cross-check the target artifact's own `attempted` flag against the state of that stage's evidence artifact: a stage with `attempted: false` may carry `STAGE_NOT_ATTEMPTED` and **no other** kind; a stage with `attempted: true` may not carry it at all. | `evidence_integrity.py::validate_modal_invocation_provenance` → `validate_stage_evidence_binding` (`:2671-2678`) | the digest-verified stage artifact is already the authority for the kind (`:1782-1789`), but nothing checks the boolean of the target artifact against it — so "not attempted" and "attempted and failed" can only be told apart by opening the stage artifact by hand (§8.2.1 d). The published artifacts carry exactly that contradiction: 14 of the 16 record `trajectory_persistence.attempted = true` while the same artifact says `persistence_status = "not_eligible"` (§8.2.1 d) |

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
| **T12** | a stage with `attempted: false` whose identity fact carries `absence_kind = "STAGE_ATTEMPT_FAILED_NO_RESPONSE"` → FAILED; and the reverse case (`attempted: true` with `STAGE_NOT_ATTEMPTED`) → FAILED | C6 — "not attempted" and "attempted and failed" must not be interchangeable |

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
| 14 | `consolidated_closure_validation_evidence.json` | — | **yes** | regenerate; must stay 21/21 PASSED, with the 14–18 rows of `HISTORICAL_EVIDENCE` unchanged and a new row added to `REPLACEMENT_EVIDENCE` whose expected verdict is `PASSED` (D8, §8.2.4 d, §9.4) |
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
5. A cost ceiling for every compute step, a separate approval for every compute step, and a
   **pre-dispatch cost estimate at or below that ceiling** — §8.2.5. The monetary ceilings of
   the three compute steps are open question **Q5** (§11.2), still unanswered; the CPU smoke
   has its own, smaller ceiling. **No** step starts without its own ceiling, its own
   approval and its own estimate: an approval for R4 approves R4 and nothing else. While Q5
   is unanswered, R3, R3b and R4 are **not dispatchable at all** — they are not "cheap enough
   to try", they are undefined.
6. **One dispatch per step.** Every compute step is a **single attempt** (D20): it is
   dispatched once, it is never retried automatically, and a retry is a new, separately named
   step with its own ceiling, its own approval and its own pre-dispatch estimate.
7. A **detached worktree** pinned at the producer commit `P` for the execution steps R3, R3b
   and R4 **and for the steps that judge their bytes (R5, R9)** (§8.2.6), so that the
   manifest, the run directory, the report and the closure all carry the same SHA.

### 8.2 The sequence

Each step is atomic: it either completes and is committed, or the tree is rolled back to
the last committed step (§8.4).

| Step | Action | Produces | Gate before proceeding |
|---|---|---|---|
| **R0** | Branch `iter-24/evidence-regeneration` from the authorised base. | — | clean tree, base SHA recorded |
| **R1** | Implement the §5 schema in the producer (`adapters.py`, `modal_app.py`, `benchmark_runner.py`), the §6.5 validator changes (**C1–C6**), the `modal_functions` fix of §8.2.1 (e) — the function list must be derived from the attempts, not from the provider — and the R3 fixture **plus its loader** of §8.2.1 (b). | code only | unit tests green; **no** published file touched; R1 does **not** yet seal the producer commit `P` — R2 does |
| **R2** | Add the §6.6 negative tests T1–T12. | tests | each test fails on the pre-fix code and passes on the post-fix code (proven by running both revisions); **R2 seals the producer commit `P`** — `P` is the commit that closes the producer surface, it is sealed *before* the first container is dispatched, and no commit after it may touch a producer path (§8.2.6, §9.3, D18) |
| **R3** | **CPU-only plumbing smoke** on one target (`AC-01` / `AccessControlVault`), run through the producer's own `execute_target()` with the inference stage **not attempted** (D17): the adapter's candidate-generator branch supplies a **checked-in, non-breaching fixture** as the candidate (D19), so the **only** stage whose attempt actually happens is `evm_sandbox`. The `inference`, `independent_replay` and `trajectory_persistence` stage blocks are still present in the artifact — the producer always writes all four stage keys (`benchmarks/adapters.py:2377-2409`) — but they record `attempted: false` (§8.2.1). | one throwaway artifact outside `benchmarks/evidence/` | the §8.2.1 gate: the stage matrix is **exactly** §8.2.1 (c); every stage **whose attempt actually happened** satisfies the §5 contract; **nothing is claimed about the stages that were not attempted** — in particular **nothing about the replay**; the caps and the approval **A-R3** of §8.2.5 hold before the first container starts, and the pre-dispatch estimate gate of §8.2.5 is passed; **R3 is a single attempt** — exactly one dispatch, no automatic retry (D20); any failure ends the step, and a retry is a new, separately named and separately approved step (§8.2.5) |
| **R3b** | **Inference-plumbing smoke** — one GPU-backed inference call for one target, to obtain a real worker-observed `function_call_id` and the client-resolved `app_id` / `container_id` for that call. The candidate comes from the model, so the verdict — and with it the replay branch — is **not** predictable in advance (§8.2.2). | one throwaway artifact outside `benchmarks/evidence/` | the §8.2.2 gate; **separately authorised** (**A-R3b**), because it spends GPU time and Modal credits; its caps of §8.2.5 — including its **hard maximum cost** — are fixed **before** the first call, and a pre-dispatch estimate at or below that ceiling exists; while the numeric ceiling of **Q5** is unanswered the step is **not dispatchable**; **R3b is a single attempt** — at most 4 Modal invocations in total, all of them inside that one attempt, and no automatic retry (D20); any failure ends the step, and a retry is a new, separately named and separately approved step (§8.2.5) |
| **R4** | Authorised live run: 16 targets, the same provider configuration as the published run (`modal_h100`, `qtum/Qwen3-Coder-30B-A3B-Audit`, `--hypotheses=3` — the flag spelling is settled at `P`, §10.1), executed from the detached worktree at `P` (§8.2.6). | a **new** run directory `run_<epoch>_<P[:7]>/` | every stage **whose attempt actually happened** has an observed-or-explicitly-`NOT_AVAILABLE` provenance, and every stage that was not attempted is recorded `attempted: false` and is not claimed; the run completes; the directory suffix equals the manifest's `git.commit_sha[:7]` (§8.2.3); the manifest's SHA is `P` (§8.2.6); the approval **A-R4**, its ceiling and a pre-dispatch estimate at or below that ceiling hold — the ceiling itself is unresolved (**Q5**) until the maintainer supplies and approves it |
| **R5** | Verify the new run **before** it becomes published: run the §5 validators over the new run dir; assert `has_synthetic_modal_uri` is false for every file; assert no `SYNTHETIC_CONTAINER_ID_RE` match anywhere. | a verification transcript | all assertions hold |
| **R6** | **Publish the new run tree additively** (D9): the new run's 16 target artifacts, its manifest, its `summary.json`, and the root-level `latest_summary.json` — which becomes the byte-identical mirror of the **new** run's `summary.json`. The published run `run_1794209615_70f5d22/` is **not** modified, moved or deleted. | new published bytes | `git diff --stat` shows only the expected files; `latest_summary.json` is byte-identical to the new run's `summary.json`; the old run directory is untouched in the diff |
| **R7** | Regenerate `modal_control_harness_validation.json` (re-pin the 32 stdout/stderr digests and the 16 `input_sha256` values over blob bytes). | new digest | the file validates against the new run dir |
| **R8** | Regenerate `modal_billing_join_table.json` (schema 3.0.0 preserved; **only the 17 harness digests change** — `source_raw_export` keeps `1529b1b9…` unless the raw export was re-exported). | new digest | `python -m benchmarks.regenerate_billing_join_table --check` → PASSED; `validate_billing_attribution` → PASSED |
| **R9** | **Do not regenerate** `iteration14..18_validation_evidence.json`: they are immutable (D8). Produce instead the **new run's own iteration report** from the new run directory. | a new report file | the old reports are byte-identical in the diff; the new report's verdict is the validator's output for the new run, recorded exactly as it is and **never relabelled**; the closure expects `PASSED` for the replacement row (§9.4) and fails if the actual verdict differs |
| **R10** | Regenerate `iteration19..23_validation_evidence.json` and `consolidated_closure_validation_evidence.json`; add the closure validator's **separate** `REPLACEMENT_EVIDENCE` table with the row for the new iteration — expected verdict `PASSED`, fixed before the run — leaving the `HISTORICAL_EVIDENCE` rows of Iterations 14–18 untouched. | new verdicts | iterations 19–23 `PASSED`; closure `21/21 PASSED` with **both** the old FAILED rows and the new row present; if the replacement's actual verdict is not `PASSED`, the closure **fails** and the run is not accepted as replacement evidence (§8.2.4 d, §9.4) |
| **R11** | Full test suite; then the complete validator sweep. | transcript | `pytest -q` green; every validator exits 0 with the expected verdict string |
| **R12** | Open a Draft PR with the full before/after inventory and the verifier transcript. | reviewable diff | maintainer approval |

### 8.2.1 The R3 gate, stated exactly

R3 exists to prove the **plumbing** of the §5 contract — the envelopes, the evidence
references, the stage block, the identity facts — on the one stage that can be exercised
without a GPU: the EVM sandbox. It proves **nothing** about the inference stage and
**nothing** about the replay stage, because neither of them is called.

#### (a) The exact control flow R3 takes

R3 does not use a separate smoke app, and it does not invent a CPU provider. It runs the
producer's own `execute_target()` — the same method the 16-target run calls — and it takes
the **candidate-generator branch that already exists in the adapter**.

| # | Step in the producer | What happens in R3 | Reference |
|---|---|---|---|
| 1 | the adapter is constructed | `candidate_generator` is a parameter of the production adapter (`benchmarks/adapters.py:1596`), stored at `:1603`. It is not a new hook: the repository already drives this very adapter through it (`benchmarks/validate_iteration16_evidence.py:597-611`, `tests/test_real_benchmark_execution.py:298`) | `adapters.py:1592-1603` |
| 2 | availability | with a candidate generator the provider check is skipped entirely (`:1666-1670`), so **no** LLM provider is contacted and no API key is needed. Modal itself must still be authenticated (`:1660-1665`), because the EVM call of R3 is a real one | `adapters.py:1657-1671` |
| 3 | candidate production | `if self.candidate_generator:` is the **first** branch of the candidate block (`:1783-1784`), so the `modal_h100` branch that calls `ProductionAuditAgent.generate_solidity_exploit.remote(...)` (`:1785-1792`) is never entered | `adapters.py:1783-1800` |
| 4 | the inference response stays empty | `inference_response` is initialised to `None` (`:1780`) and is assigned only inside the two provider branches, so the inference capture is `attempted=False` (`:2260-2270`) | `adapters.py:1780`, `:2262` |
| 5 | the refinement loop cannot fire | the closed-loop refinement requires `self.candidate_generator is None` (`:1838`), so R3 cannot make a second, hidden inference call | `adapters.py:1833-1840` |
| 6 | **one** Modal call | the candidate is verified by the real CPU worker: `verify_exploit_remote.remote(target_dict, payload_dict)` (`:1826`), a CPU function (`modal_app.py:550-556`, `cpu=config.SANDBOX_CPU_CORES`) | `adapters.py:1826`, `modal_app.py:550-556` |
| 7 | the replay branch is **not** entered | the producer dispatches `verify_replay_remote` only if `verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED` (`:1882-1885`). R3's fixture does not breach the invariant, so the branch is not taken, `replay_attempted` stays `False` (`:1875`) and the replay capture is `attempted=False` (`:2282-2294`) | `adapters.py:1875`, `:1882-1883`, `:2284` |
| 8 | the persistence branch is **not** entered | persistence runs only `if is_verified` (`:2133`), and `is_verified` requires a confirmed replay (`:2104-2109`) — which R3 cannot have | `adapters.py:2104-2109`, `:2133` |
| 9 | the provenance block is the published one | the stage block is written by the same code the 16-target run uses (`:2362-2411`), with **all four** stage keys always present (`:2377-2409`) | `adapters.py:2362-2411` |

The empirical confirmation that the replay branch is the exception and not the rule: in the
published run only **2 of the 16** targets have a replay at all — `AC-01` and `REENT-01` are
the only targets with `*_replay_stdout.txt` files, and they are the only two whose artifacts
record `independent_replay.attempted = true`. The other fourteen never reach the branch.

#### (b) The payload source — and why it fabricates nothing

R3's candidate is a **checked-in fixture**, not a model output:

* **R1** adds the fixture to the repository as a tracked file
  (`benchmarks/evidence/fixtures/r3_smoke_candidate_ac01.sol`) together with the loader that
  turns it into the `ExploitPayload` the adapter expects. The file's SHA-256 is recorded in
  the smoke transcript, so the artifact is bound to the exact bytes that were sent to the
  EVM worker. The bypass mechanism itself needs no new code — only the fixture and its
  loader are new (D17, D19).
* The fixture is a **negative control**: it compiles against the trusted harness of the
  target (`AccessControlVault` — the target of `AC-01`; the harness file is read by the
  adapter at `adapters.py:1746-1755`, and the allowlist that maps a target to its harness is
  `sandbox/runner.py:29-44`), it runs, and the trusted harness returns **no** breach
  verdict. A negative control is what makes the smoke honest: it cannot produce a "verified
  breach", and it therefore cannot be mistaken for a finding.
* It is **never presented as model output**: the inference stage is recorded
  `attempted: false`, its three identity facts are `not_available` with the absence kind
  `STAGE_NOT_ATTEMPTED`, and the artifact is written **outside** `benchmarks/evidence/` (a
  throwaway directory), so no report, no manifest and no closure can ever refer to it.
* Precedent: the producer rehearsal of Iteration 16 already drives this adapter with an
  injected payload (`benchmarks/validate_iteration16_evidence.py:597-611`). R3 differs from
  that rehearsal in exactly two ways — the EVM call is **real** (not mocked) and the
  candidate comes from a **tracked file** (not from an inline literal).

**If the fixture unexpectedly breaches the invariant**, the producer dispatches the replay
(`:1882`), the artifact records `independent_replay.attempted = true`, and R3's negative
control is broken. In that case R3 **fails its gate**, the step is stopped and the
discrepancy is recorded. R3 is not re-interpreted as a replay test: the replay stage is
R3b's business, and there its trigger is the model's candidate, not a fixture.

#### (c) The stage matrix of R3

| Stage | State (`STAGE_STATE_TABLE`) | `attempted` | `function_name` | What R3 proves about this stage |
|---|---|---|---|---|
| `inference` | `NOT_ATTEMPTED` | **false** | `null` — after R1's fix; today the producer writes the provider's function name here (e, item 7) | nothing. The block is present because the producer always writes all four keys (`adapters.py:2377-2409`); its `attempted: false` is the honest statement |
| `evm_sandbox` | `EXECUTED_WITH_RUNTIME_ENVELOPE` (or `EXECUTED_NO_RUNTIME_ENVELOPE`) | **true** | `verify_exploit_remote` | the real CPU worker call; the worker-observed `function_call_id`; the client-observed `app_id` / `container_id`; the eight remote-EVM facts of §5.4; the stage's own evidence artifact |
| `independent_replay` | `NOT_ATTEMPTED` | **false** | `null` | **nothing.** The replay function is not called by R3, so R3 says nothing about `verify_replay_remote` — neither about its `function_call_id` nor about its `container_id` |
| `trajectory_persistence` | `NOT_ATTEMPTED` | **false** | `null` | nothing. Persistence requires a confirmed replay (`:2104-2109`), which cannot exist here |

**The Modal invocations of R3 are exactly one:** `verify_exploit_remote` (CPU). No GPU call,
no replay call, no persistence call. The pre-dispatch estimate of §8.2.5 is computed over
that one invocation.

**R3 is a single attempt.** The step is dispatched once; there is no automatic retry. If that
one attempt fails — the container fails to start, the call times out, the worker returns no
response — R3 **ends** there: the failure is recorded, the app is stopped, and the sequence
does not continue into R3b. A retry is **not** a second attempt of R3: it is a **new,
separately named step** (for example `R3r`) with its own approval, its own ceiling and its own
pre-dispatch estimate (D20, §8.2.5). The count is therefore exact and has no second path:
**the worst-case Modal invocation count of R3 is 1.**

#### (d) "Not attempted" is not "attempted and failed"

The two states are already distinguishable in the bytes, and the distinction is enforced on
the side that matters:

* the producer derives the four flags of a stage from its capture
  (`adapters.py:2259-2308`) and the identity facts from the state those flags describe:
  `build_stage_identity_facts` → `classify_stage_absence` → `STAGE_STATE_TABLE`
  (`evidence_integrity.py:1303-1340`, `:1356`; `ABSENCE_KIND_RULES` `:636-660`);
* a stage that was never invoked may carry `STAGE_NOT_ATTEMPTED` only, and that kind is
  allowed in exactly one state — `NOT_ATTEMPTED` (`:637-640`). A stage that was invoked and
  failed is a **different** state (`ATTEMPT_FAILED_NO_RESPONSE`, `:590`, `:610`) with a
  different kind (`:641-644`);
* the digest-verified stage evidence artifact is the authority, and the fact in the target
  artifact may not disagree with it (`evidence_integrity.py:1782-1789`).

**The published artifacts show exactly this defect.** In **14 of the 16** published target
artifacts the persistence stage is recorded `attempted: true` with
`function_name: "record_trajectory_remote"`, while the *same* artifact records
`tool_metadata.remote_stages.trajectory_persistence = "not_eligible"` and
`tool_metadata.persistence_status = "not_eligible"` — the stage was never eligible and the
function was never called. The producer revision at this PR head derives the flag from the
status (`adapters.py:2255`) and the function name from the same flag (`:2401-2408`), so the
contradiction is gone in the code; what is missing is a **validator** that refuses an
artifact in which the flag and the rest of the artifact disagree (C6). The published
artifacts also carry the `attempted` key on only **two of the four** stages — `inference`
and `evm_sandbox` have no `attempted` key at all — which is the gap §5.1 closes.

**The remaining gap is that no validator cross-checks the target artifact's own `attempted`
flag against that authority.** The validator iterates the stages the artifact *contains* and
asks only whether the three identity fields are present and well-formed
(`evidence_integrity.py:2551-2577`); it never reads `attempted`. §6.5 **C6** closes that
gap: a stage whose `attempted` is `false` may carry `STAGE_NOT_ATTEMPTED` and nothing else,
and a stage whose `attempted` is `true` may not. Until C6 is implemented, R3's gate checks
the state itself (it reads the stage evidence artifact directly) instead of relying on the
validator to do it.

#### (e) What the R3 gate asserts

1. **Every stage whose attempt actually happened** satisfies the §5 contract: its three
   identity facts are `observed(...)` / `not_available(...)` envelopes — no bare strings,
   no `modal-app://`, and no `durable_log_ref` / `provider_log_uri` / `log_uri` key at all.
2. **Every `not_available` envelope** carries a reason, an absence kind from
   `ABSENCE_KINDS`, an `observed_by` side, and an `evidence_ref` whose digest verifies. The
   last requirement means the validator must be called **with an evidence root**:
   `validate_modal_invocation_provenance(artifact, evidence_root=<smoke run dir>/baseline_5)`.
   Without `evidence_root` the referenced bytes cannot be resolved and the validator rejects
   **every** `NOT_AVAILABLE` fact with "no evidence root was provided"
   (`evidence_integrity.py:428-456`). The published Iteration 14 validator calls it *without*
   that argument (`validate_iteration14_evidence.py:185`), while Iteration 15 passes
   `evidence_root=run_dir / baseline_id` (`validate_iteration15_evidence.py:254`) — the smoke
   must follow the latter form.
3. **The stage matrix is exactly §8.2.1 (c)**: `inference: false`, `evm_sandbox: true`,
   `independent_replay: false`, `trajectory_persistence: false` — and the state of every
   stage is one of the five states of `STAGE_STATE_TABLE`
   (`evidence_integrity.py:608-614`).
4. **The remote-EVM block** of the smoke artifact passes
   `validate_remote_evm_toolchain_provenance(artifact)` (`evidence_integrity.py:3557`): all
   eight facts of `REMOTE_EVM_REQUIRED_FACTS` (`evidence_integrity.py:3510`) are sourced
   `observed(...)` envelopes, or explicit `not_available(...)` with a reason and an evidence
   reference.
5. **The run-level block** validates: the identity field (§5.2, name open per Q1) is an
   envelope, `target_id` and `correlation_id` are present.
6. **No synthetic identity**: no string in the artifact matches `SYNTHETIC_CONTAINER_ID_RE`
   and none is in `FORBIDDEN_SYNTHETIC_CONTAINER_IDS`.
7. **The function names agree with the attempts.** A stage that was not attempted records
   `function_name: null` — the §5.1 schema allows it (`str | null`) — and the run-level
   `tool_metadata.modal_functions` names only the functions that were actually invoked: for
   R3 that is `verify_exploit_remote` alone. Two places in the producer get this wrong
   today. `modal_functions` is built from the **provider** and not from the attempts
   (`adapters.py:2154-2163`), so with `provider="modal_h100"` it would name
   `ProductionAuditAgent.generate_solidity_exploit` although no such call was made. And the
   `inference` stage's `function_name` is likewise taken from the provider
   (`adapters.py:2246-2254`, `:2378-2384`) instead of from the attempt — while the
   `independent_replay` and `trajectory_persistence` stages already derive their name from
   the attempt (`:2392-2400`, `:2401-2408`). **R1** fixes all three. Until it is fixed, R3's
   gate checks them against the recorded attempts and reports the discrepancy instead of
   ignoring it.

#### (f) What R3 must NOT claim

R3 does **not** verify the inference stage and does **not** verify the replay stage, and no
artifact, report, commit message or PR description may say that it does. Specifically, R3
does not establish:

* that the `inference` stage's `function_call_id` is worker-observed — no inference call is
  made at all;
* that the `inference` stage's `app_id` or `container_id` resolves against the provider's
  call graph (`call_graph_inputs` → `containers_of_app` → `task_app_id`, §4.1);
* that the smoke artifact is comparable with the published run's `inference` block;
* any end-to-end statement about the inference path;
* **that the replay plumbing works** — `verify_replay_remote` is never called by R3, so R3
  establishes nothing about the replay's `function_call_id`, its `container_id`, its evidence
  artifact or its absence kinds;
* anything about the 16-target behaviour.

The reason the first two points are structural, not a matter of extra effort:
`validate_modal_invocation_provenance` iterates the stages the artifact *contains* (`for
stage_name, stage in stages.items()`, `evidence_integrity.py:2551`) and asks only whether
the three identity fields are present and well-formed (`evidence_integrity.py:2555-2577`) — it
never reads the `attempted` flag. A stage block whose attempt never happened therefore passes
the stage checks **without proving anything about inference** — and the plan must not let
that pass be read as inference evidence. This is exactly why the §5 contract requires the
attempt flag to be explicit: the honest statement is "the `inference` stage was not
attempted", never "there was no `inference` stage" — the key is always written
(`benchmarks/adapters.py:2377-2409`). `MODAL_PROVENANCE_STAGES`
(`evidence_integrity.py:1806`) cannot be used to constrain the stage set either: it is
defined once and referenced nowhere in the repository, so no validator constrains the stage
set.

### 8.2.2 R3b — the inference-plumbing smoke, as a separate authorised step

The `inference` stage cannot be exercised on CPU: it is the stage that calls the model
(`ProductionAuditAgent.generate_solidity_exploit`, the `modal_h100` provider with
`qtum/Qwen3-Coder-30B-A3B-Audit` in the published configuration, §10.1). Proving that the
inference provenance is honest therefore requires an actual inference call.

That call is **not** part of R3 and is **not** authorised by this plan. It is step **R3b**, a
separate and explicitly authorised action with its own gates:

| Aspect | R3 (CPU) | R3b (GPU) |
|---|---|---|
| Stages exercised | `evm_sandbox` **only** | `inference` and `evm_sandbox`; `independent_replay` **only if** the model's verdict triggers it (`adapters.py:1882`), and `trajectory_persistence` only if that replay confirmed the breach (`:2104-2109`) |
| Modal invocations | exactly **1** (`verify_exploit_remote`) | **1** GPU inference call + **1** CPU verify + **≤ 1** CPU replay + **≤ 1** CPU persistence — worst case **4**, all of them inside the step's **single** attempt (§8.2.5, D20) |
| Cost | CPU containers only — its own, smaller ceiling | one GPU inference call — Modal credits — its own **hard maximum cost** (§8.2.5) |
| Authorisation | its own approval **A-R3** (§8.2.5) | **separate, explicit authorisation** **A-R3b** |
| Proves | the producer/validator plumbing, the envelopes, the evidence references, the EVM fact sourcing | that the inference `function_call_id` is worker-observed, and that the client resolves the provider-issued `app_id` / `container_id` for that call — and, **only if** the replay was actually dispatched, that the replay stage's identities resolve as well |
| Does **not** prove | anything about inference; **anything about the replay** | the 16-target behaviour |

**R3b's stage matrix is outcome-dependent, and that is recorded, not assumed.** Its
candidate comes from the model, so whether the replay branch is entered is decided by the
verdict and not by the plan:

| Stage | Expected in R3b | Condition |
|---|---|---|
| `inference` | `attempted: true` | always — the GPU call is the point of R3b |
| `evm_sandbox` | `attempted: true` | always — the candidate is verified |
| `independent_replay` | `attempted:` **either** `true` or `false` | `true` only if the model's candidate breaches the invariant (`adapters.py:1882`); `false` otherwise. R3b **records** which of the two happened and claims the replay **only** when it is `true` |
| `trajectory_persistence` | `attempted:` **either** `true` or `false` | `true` only if the replay confirmed the breach (`is_verified`, `adapters.py:2104-2109`) |

A smoke report that says "the replay stage was exercised" is therefore only true if the
artifact records `independent_replay.attempted = true`. A report that says it was **not**
exercised is true in every other case, and is not a defect of the smoke.

**R3b is a single attempt.** Like R3 (D20), R3b is dispatched once and is never retried
automatically. Its worst case of 4 Modal invocations is the **content of that one attempt** —
the GPU call plus the CPU stages the model's verdict may trigger — not a budget that may be
spent twice. If the attempt fails, R3b ends there: the failure is recorded, the app is
stopped, and the sequence does not continue into R4 (§8.3). A retry is **not** a second
attempt of R3b: it is a **new, separately named step** (for example `R3br`) with its own
approval (**A-R3br**), its own hard maximum cost and its own pre-dispatch estimate.

R3b must run **before** R4, and its result must be recorded, because R4 is a 16-target paid
run: if the inference plumbing is broken, R4 would spend the whole budget to produce 16
artifacts that cannot be published. Making R3b a separately authorised step — rather than a
hidden sub-step of R3 — is what keeps the authorisation boundary honest. This plan spends
nothing and authorises nothing.

**R3b's hard maximum cost is a separate number, and it is still unset.** R3b spends GPU
credits *before* the ceiling of R4 exists, so it cannot borrow R4's budget: it has its own
ceiling (**Q5**), its own approval (**A-R3b**) and its own pre-dispatch estimate gate
(§8.2.5). While that numeric ceiling is unresolved, R3b is **not dispatchable** — the
sequence stops at R3 with a recorded "not dispatched — no ceiling" instead of continuing into
a paid call whose cost nobody has bounded.

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
by the name of a summary file — and, explicitly, **not by reading the root-level
`latest_summary.json`**: that file is a byte-identical mirror of one run's `summary.json`
(D12, §7.4 row 4), and using it as a pointer to "the current run" would re-introduce
precisely the implicit selection this section forbids. A validator reads exactly the
directory it was told to read, and the two literals above are the only two places where the
new run is named. The negative test **T11** pins this: a *newer* run directory in the tree is
not selected, because nothing ever enumerates the tree.

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

**The actual verdict is reported honestly in every case.** A replacement run that does not
reach `PASSED` is recorded as a failed replacement: its own report carries the validator's
real output, the closure fails on that row, the run is **not** accepted as replacement
evidence, and no report, commit message or PR description relabels it. The expectation
`PASSED` is a requirement the run has to meet — not a description of what the run produced.

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
its own stop condition and its own explicit approval — fixed **before** the step runs — and
its own **pre-dispatch cost estimate** that must be at or below its ceiling before the first
container is dispatched.

#### The caps

| Step | Compute | Hard cap | Timeout / stop condition |
|---|---|---|---|
| **R3** (CPU plumbing smoke) | **exactly 1** Modal invocation — the CPU `verify_exploit_remote`; 1 CPU container, 1 target (`AC-01`), **0** inference calls, **0** replay calls, **0** persistence calls (§8.2.1 a, c) | **1** container, **1** target, `--hypotheses=1`, **exactly 1 attempt** — no automatic retry (D20) — a wall-clock budget of **20 minutes** for that attempt, and a **monetary ceiling of its own** (Q5) | the per-call timeout stays at the published value (`timeout_sec = 120`, §10.1); the client aborts the attempt at the 20-minute budget, stops the app (`modal app stop`) and records the failure; **any failure ends the step** — there is no second attempt, and a retry is a new, separately named and separately approved step (D20) |
| **R3b** (inference-plumbing smoke) | **worst case 4** Modal invocations — **1** GPU inference call + **1** CPU `verify_exploit_remote` + **≤ 1** CPU `verify_replay_remote` + **≤ 1** CPU `record_trajectory_remote` (§8.2.2); 1 GPU container (`modal_h100`), 1 target, **exactly 1** inference call — all of them inside the step's **single** attempt | **1** GPU call, `--hypotheses=1`, **exactly 1 attempt** — no automatic retry (D20) — whose worst case is the 4 invocations above, a wall-clock budget of **20 minutes**, and a **hard maximum cost** of its own (Q5) | the same abort rule; **any failure ends the step** — a failed R3b **ends the sequence**, R4 does not start (§8.3); there is no second attempt, and a retry is a new, separately named and separately approved step (D20) |
| **R4** (the 16-target run) | 16 targets × H100, the published configuration — **one** authorised run: the 16 targets are dispatched once, and a target that fails inside the run is that target's recorded result, not a retried attempt (D20) | the monetary ceiling of **Q5** (§10.3) — no per-call cost may exceed it — and **exactly 1** run attempt (D20) | the per-call timeout stays at `timeout_sec = 120` per target; the operator stops the app when the accumulated spend reaches the ceiling; the partial result and its billing window are published, and the run is **not** retried silently |

Two invariants apply to all three steps:

* **A cap is a stop condition, not a target.** The step stops when the cap is reached; it
  never continues because the result is "almost" there.
* **Every step is a single attempt (D20).** "Exactly 1 attempt" means **one** invocation of
  the step in total — not one plus a hidden retry. There is no automatic retry: a step that
  fails ends there, the app is stopped and the failure is recorded. A retry is **not** a
  second attempt of the same step; it is a **new, separately named step** (for example `R3r`,
  `R3br`, `R4r`) with its own approval, its own monetary ceiling, its own pre-dispatch
  estimate and its own record in the approval table of the PR (below). The one-attempt rule
  is what makes the invocation maxima exact rather than approximate: **exactly 1** Modal
  invocation for R3 and **at most 4** for R3b, with no second path (D20, §8.2.1 c, §8.2.2).

The monetary ceilings of R3, R3b and R4 are **three separate numbers**, each attached to the
approval of the respective step. **Q5** (§11.2) holds all three of them — the GPU smoke
R3b, the 16-target run R4, and, with its own, smaller number, the CPU smoke R3, because a
CPU container is a separate authorisation and not a free preliminary. None of the three
numbers is set by this plan, and a step whose ceiling is unset is **not dispatchable**: the
pre-dispatch gate below is the mechanism, and an unresolved ceiling means the gate cannot be
passed.

#### The pre-dispatch cost gate

A cap that is only checked *afterwards* is not a gate. Before any container is dispatched,
the step must pass a **pre-dispatch estimate gate** — three conditions, all of them checked
*before* the dispatch:

1. **The ceiling exists and is approved.** The step's monetary ceiling is a number, written
   down, and attached to that step's approval (**A-R3**, **A-R3b**, **A-R4**). The three
   ceilings are open question **Q5** (§11.2) and are **not yet set**; until the maintainer
   supplies and approves them, R3, R3b and R4 are **not dispatchable at all**. An unresolved
   ceiling is not a generous default — it is the absence of a budget, and this plan does
   not invent one.
2. **An estimate exists.** The estimate is the **worst case** the step can spend under its
   own caps: the provider's published rate for the declared resources, multiplied by the
   step's hard wall-clock budget — and by the **number of Modal invocations the step can
   actually make**. Because every step is a single attempt (D20), there is **no attempt
   multiplier**: the estimate covers the one attempt, and a retry — a separately named step —
   needs its own estimate against its own ceiling. For R3 that is one CPU container × its
   20-minute budget × 1 attempt; for R3b it is one H100 container × 20 minutes × 1 attempt
   **plus** the CPU invocations of that same attempt (one `verify_exploit_remote`, at most
   one `verify_replay_remote`, at most one `record_trajectory_remote` — §8.2.2). The rate is an
   **input to the approval**, recorded with its source and its date; it is never hardcoded
   in the repository, for the same reason the producer does not hardcode cost estimates
   (`benchmarks/adapters.py:19` — "No hardcoded cost estimates: unmeasured runs report
   cost_usd as None"; the published `summary.json` carries `cost_status: "unmeasured"` and
   `cost_usd: null`, `benchmarks/artifacts/run_1794209615_70f5d22/summary.json:167-168`).
3. **The estimate is at or below the ceiling.** If `estimate > ceiling`, the step is **not
   dispatched**: either the ceiling is raised by a new, explicit approval, or the compute cap
   (container count, wall-clock budget) is lowered until the worst case fits under it. A retry
   step is not covered by this gate: it has its own ceiling, its own approval and its own
   estimate at or below that ceiling.

**If the estimate is unavailable, the step does not start.** "Unavailable" means: the
provider publishes no rate for the requested resources, the workspace's billing data cannot
be read, the rate cannot be obtained from the provider's own documentation at dispatch
time, or the estimate command fails. In every one of those cases the step is recorded as
**"not dispatched — estimate unavailable"**, with the reason — never as "dispatched, cost
unknown, we will see". The repository already holds the pattern for this: the CPU smoke's
billing collection returns the provider's own line items or an explicit `NOT_AVAILABLE` with
the exact reason and the failed command, and states that the value "is never estimated"
(`benchmarks/run_iteration19_cpu_smoke.py:169-204`).

**After the dispatch, the actual spend is read back from the provider and compared with the
ceiling.** The provider's billing report is the only source of the actual spend
(`modal billing report --for today --resolution h --show-resources --json --profile <p>`,
as `benchmarks/run_iteration19_cpu_smoke.py:177-189` already invokes it). The comparison is
part of the step's approval record; an overrun aborts the step (`modal app stop`) and is
recorded as an overrun. The estimate is a *pre-dispatch* bound, the provider's report is the
*post-dispatch* fact — they are different records and both are kept.

#### The approval boundaries

| Approval | Covers | Does **not** cover |
|---|---|---|
| **A-R3** | R3 only: the CPU container, one target, one hypothesis, the CPU ceiling — and the pre-dispatch estimate at or below that ceiling | R3b (GPU), R4 (16 targets, H100) |
| **A-R3b** | R3b only: one GPU inference call for one target, the GPU hard maximum cost — and the pre-dispatch estimate at or below that ceiling | R3, R4 |
| **A-R4** | R4 only: the 16-target H100 run, the Q5 ceiling — and the pre-dispatch estimate at or below that ceiling | R3, R3b, and any retry step of either — a retry is a separate step with a separate approval (D20) |

The rules:

1. **Approval for R4 does not approve R3 or R3b, and approval for R3 does not approve R3b.**
   Each step is authorised separately, in writing, with its own ceiling attached.
2. **Approval for R3b does not approve R4.** R3b exists to prove the inference plumbing
   *before* the expensive run; if it fails, the sequence stops at R3b (§8.3) and R4 needs a
   **new** approval, not the old one.
3. **One approval covers one attempt.** The approval of a step covers exactly the attempt its
   cap states — and the cap states **one**, because no step is retried automatically (D20).
   There is no approval of the form "the step and a second try if it fails": a retry is a
   **new, separately named step** (for example `R3r`) with its own approval (for example
   `A-R3r`), its own ceiling, its own pre-dispatch estimate and its own row in the approval
   table of the PR.
4. **The approval record is part of the PR.** The PR of the regeneration iteration records,
   per step: the approver, the date, the approved ceiling, the pre-dispatch estimate with
   the rate source it was computed from, and the actual spend read back from the provider. A
   step without that record did not run.
5. **No approval implies an estimate.** The pre-dispatch estimate belongs to the approval of
   the step it belongs to: the estimate of R3b is part of **A-R3b**, not of **A-R4**. An
   estimate prepared for R4 does not authorise R3b, and the absence of an estimate stops the
   step it was prepared for.
6. **This plan approves nothing.** It specifies the caps, the estimates and the boundaries;
   no approval is given here, no container was started, and no credits were spent while
   producing it.

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

1. **R1 and R2 together produce the producer commit `P`, and `P` is sealed after R2.**
   `P` is the commit that closes the producer surface: the last commit that touches
   `modal_app.py` (repository root), `benchmarks/adapters.py`,
   `benchmarks/benchmark_runner.py` or the validators. R2 adds the negative tests T1–T12, so
   `P` is the **R2** commit — or any commit that contains both changes — and it is sealed
   *before* the first container is dispatched. No commit after `P` may touch a producer path
   — that is what makes P6.14's diff empty (§9.3) and what makes the invalidation rule of
   item 10 unambiguous.
2. **R3, R3b and R4 are executed from a detached worktree at `P`, and so are the two steps
   that judge their bytes (R5, R9):**

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
8. **Which commit is checked out, per step.** One value, no ambiguity:

   | Step | Checked-out commit | What it binds |
   |---|---|---|
   | R3, R3b, R4 — the execution steps | the detached worktree at `P` | the manifest's `git.commit_sha`, the run directory's suffix, the executed producer bytes |
   | R5 — the verification of the new bytes; R9 — the replacement report | the same detached worktree at `P` | the report's `code_sha` **and** the validator bytes that produced it |
   | R7, R8 — harness and join table; R10 — iterations 19–23 + closure; R11 — the suite | the branch head at that moment, i.e. the **closure commit** | the closure's own binding; P6.13's per-row `--code-sha` and P6.14's diff are computed against that commit |

   The middle row is the point: the report that judges the run must be produced by the
   **same** code that produced the run, otherwise the report is evidence about a different
   version of the producer. The last row is the other half of the rule: the closure
   validator's own change (the new `REPLACEMENT_EVIDENCE` row, §8.2.4 d) is a change to the
   **judging** harness, not to the producer — it is therefore allowed after `P`, and it is
   bound to the closure commit.
9. **The executed producer bytes are verified by digest, not by trust.** The manifest's SHA
   binds the *commit*; a digest binds the *bytes*. For every producer path, the run's
   verification transcript records
   * the git blob id of the file at `P` (`git rev-parse <P>:<path>`) and the blob id of the
     file in the executing worktree (`git hash-object <path>`) — they must be equal; and
   * the SHA-256 digest over the **LF** bytes of the file at `P` (`git show <P>:<path>`) and
     over the LF bytes of the file in the worktree — they must be equal, in the one digest
     convention of this repository (D10, §1.3).

   The worktree's `git status --porcelain` is empty (item 3) and the manifest's
   `git.is_dirty` is `false`; the digest comparison is what makes that meaningful, because
   it compares the **bytes that ran** with the bytes of `P`, not merely the presence of a
   commit.
10. **A source-changing commit between the capture and R4 invalidates the run.** If any
    commit after `P` touches a producer path, then the code that produced the capture is no
    longer the code in the tree, and P6.14's diff is no longer empty. The consequences are
    fixed in advance and are not negotiable:
    * the run is **invalid** — it is not published, not bound to the closure, and not
      re-labelled;
    * a **fresh capture** is required: a new run from a new producer commit `P'`, a new run
      directory named after `P'[:7]`, a new manifest, a new report and a new
      `CAPTURE_BINDINGS` entry — the invalid run's bytes stay where they are, as a
      discarded attempt outside the published tree;
    * the closure binds the **new** capture. The invalid capture is not added as a second
      binding: a binding exists per capture the closure asserts, and an invalid capture
      asserts nothing.

    A commit after `P` that touches **no** producer path — the closure validator's new row,
    a published report, a document — does **not** invalidate the run: the run stays bound to
    `P`, and the closure stays bound to the closure commit (§9.3).

**The manifest must never claim a SHA other than the code that actually executed.** That is
why the plan does not "fix up" the SHA afterwards, and why the worktree is detached: a
detached worktree at `P` is the only arrangement in which the manifest's SHA, the
directory's suffix, the report's `code_sha` and the closure's capture binding are the same
value *by construction* rather than by coincidence. The digest comparison of item 9 closes
the remaining gap: the commit identity says *which* code, the digest says *that* code —
byte for byte — is what ran.

If a later step (a test, a document, a published report) advances the branch, **nothing
about the run changes**: the run stays bound to `P`, and the closure is bound to the closure
commit. The two are related by ancestry — `P` is an ancestor of the closure commit — which is
exactly what P6.14 asserts. The one exception is a commit that touches a producer path:
that invalidates the run and forces a fresh capture (item 10, §9.3).

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
broken, and R4 requires its own approval in any case. There is **no automatic retry** of a
failed smoke: every smoke is a single attempt (D20), so a retry is a **new, separately named
step** with its own approval, its own ceiling and its own pre-dispatch estimate — it is
recorded as its own step in the sequence and in the PR, never as a second try of R3 or R3b.

**All three execution steps run in the same detached worktree** at the producer commit `P`
(§8.2.6) — and so do the two steps that judge their bytes (R5, R9) — so the smoke, the run
and the report that describes it are produced by exactly the code the closure will later
bind to. The worktree holds no published bytes — it is removed with
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
| Verdicts | `FAILED (0/16)` — unchanged | the validator's output against the new run — **expected `PASSED`**, fixed before the run (§9.4); a different result fails the closure and is reported as it is |
| Artifacts | `run_1794209615_70f5d22/` — unchanged, in place | the new `run_<epoch>_<sha7>/` (D9) |
| Role in the closure | rows 14–18 of `HISTORICAL_EVIDENCE`, expected string `FAILED (0/16 targets)` | a **new row** in `REPLACEMENT_EVIDENCE`, expected string `PASSED` — fixed before the run (§8.2.4 d, §9.4) |

The closure therefore refers to **both**: the 14–18 rows keep asserting that the historical
verdicts are still exactly `FAILED (0/16 targets)`, and a new row asserts `PASSED` for the
replacement run — the expectation fixed before the run (§8.2.4 d, §9.4). The closure report
states both in the same artefact, so a reader sees the failure and its replacement side by
side — with the failure still there.

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
about the artifacts they were computed from. If the replacement run does not reach `PASSED`,
the outcome is reported as it is: the closure **fails** on the replacement row, the run is
**not** accepted as replacement evidence, and R12 opens a Draft PR that says so. A failed
replacement is a legitimate result of an authorised experiment — and it is never relabelled
into a pass, and the historical FAILED rows are never edited to match it.

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

**A source-changing commit after `P` invalidates the capture.** P6.14's diff is the
detector: if a commit after `P` touches `modal_app.py`, `adapters.py` or
`benchmark_runner.py`, the diff is no longer empty and the closure fails on the replacement
binding. The plan's rule for that failure is fixed in advance (§8.2.6 item 10): the run is
**invalid** and a **fresh capture** is required — a new run from a new producer commit, a
new run directory, a new manifest, a new report and a new `CAPTURE_BINDINGS` entry. The
invalid capture is not added to the table, and the run it produced is not published. A
commit after `P` that touches no producer path invalidates nothing: the historical binding
stays exactly as it is, and the replacement binding keeps comparing `P` with the closure
commit over the three producer paths.

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

Under D8 the closure's requirements change in exactly one way: a **separate table**,
`REPLACEMENT_EVIDENCE`, is added with a **row** for the replacement iteration (§8.2.4 d).
`HISTORICAL_EVIDENCE` itself is **not** touched — neither the rows for Iterations 14–18 (their
expected verdict string `FAILED (0/16 targets)` and their bound `code_sha`) nor the rows for
19–23. And because the bytes of the old run directory are left alone as well (§7.4 row 17),
those validators keep producing the same output, so the old rows keep matching.

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
| the bound `code_sha` | when `P` is sealed (after R2), before any run | `P` — the producer commit the run executes from (§8.2.6) |
| the run directory | the SHA part when `P` is sealed (`P[:7]`); the epoch part by the run itself (`benchmark_runner.py:357`) | `benchmarks/artifacts/run_<epoch>_<P[:7]>` — a literal, transcribed into the new module and into `REPLACEMENT_EVIDENCE` when the run directory exists, and **verified** against the manifest by the check of §8.2.4 (c), so a wrong transcription cannot pass |

Writing the expectation *after* the run would make the check unfalsifiable — the closure
would assert whatever the run produced, which is the same defect as the conditional rule D8
forbids. Written in advance, the check has a real failure mode: **if the replacement run
does not pass, the closure fails**, R12 opens a Draft PR that reports the failure, and the
historical FAILED rows stay exactly as they are. The plan does not promise that the new row
can be satisfied; it states what it requires. The actual result is still reported honestly —
the replacement report carries the validator's real output, and it is never relabelled to
match the expectation.

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

**The flag spelling is settled at `P`, not here.** The argv above is the one the runner
builds (`benchmarks/adapters.py:1647-1655` for the default argv, `:1681-1690` for the
per-target command) and the one the published artifact records. The entrypoint it calls
must accept exactly those flags **at the producer commit**: the current `modal_app.py`
entrypoint (`modal_app.py:1308-1315`) takes `--mode`, `--target-name`, `--num-candidates`,
`--max-rounds` and `--use-lora`, and accepts neither `--hypotheses`, nor `--provider`, nor
`--model`. Reconciling the entrypoint with the runner's argv is part of R1's producer work,
because the entrypoint *is* the producer. What the regeneration must preserve is the
**configuration** — `modal_h100`, `qtum/Qwen3-Coder-30B-A3B-Audit`, `max_hypotheses = 3`,
`timeout_sec = 120`, the same 16-target allowlist — not the spelling of a flag.

### 10.2 The capture sequence

1. **Pre-flight (no cost):** confirm the app exists and the model is available; confirm the
   worker image contains `forge`; confirm the client can reach the provider's container
   listing (`ModalProvider.containers_of_app`).
2. **CPU plumbing smoke (small cost):** one target, executed through the producer's own path
   with the inference stage not attempted — this is **R3** (§8.2.1, D17, D19). The mechanism
   is the adapter's **existing** `candidate_generator` parameter (`benchmarks/adapters.py:1596`,
   `:1603`, used at `:1783-1784`), so **no new CPU mode has to be invented**: with a
   candidate generator the provider dispatch is short-circuited before the GPU call, the
   refinement loop cannot fire (`:1838`), and the smoke makes exactly one Modal call — the
   real CPU `verify_exploit_remote` — and the step is a **single attempt**: it is dispatched
   once, and a failure ends it (D20). R1 adds only the **fixture and its loader** (§8.2.1 b).
   There is still **no** `modal_cpu` provider choice in the code: the runner's `--provider`
   accepts `gemini` / `openai` (`benchmarks/benchmark_runner.py:741`) and the Baseline-5
   backend accepts `modal_h100` / `modal_t4` / `gemini` / `openai` (`:743-745`), while the
   adapter branches on exactly those two Modal providers
   (`benchmarks/adapters.py:1624-1626`) — which is why R3 is *not* expressed as a provider
   flag. The repository's separate CPU-only app (`benchmarks/modal_cpu_smoke_app.py`, `gpu=None`,
   `cpu=0.5`, `memory=256`, `timeout=60`, `retries=0`) is **not** R3: it proves that a real
   worker reports its own runtime identity, but its record is a single-function identity
   record, not the §5 stage block of a target artifact — it belongs to the pre-flight
   (step 1). Assert the §5 contract for the stages R3 actually ran — which is exactly one —
   before any paid run. A CPU container is still Modal compute and still costs money, so R3
   has its own ceiling, its own approval **A-R3** and its own pre-dispatch estimate gate
   (§8.2.5).
3. **Inference-plumbing smoke (minimal GPU cost):** one target with the published inference
   configuration, exercising the `inference` stage and resolving its provider-issued identities
   — this is **R3b** (§8.2.2), and it needs its **own explicit authorisation** **A-R3b** with
   its cap fixed before the first call (§8.2.5). It is a **single attempt** (D20): dispatched
   once, never retried automatically, and any failure ends it.
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
| Per-step ceilings | **three separate numbers** — the CPU ceiling of R3, the GPU hard maximum cost of R3b, and the ceiling of R4 (§8.2.5). All three are **not yet set** — open question **Q5** (§11.2); a step whose ceiling is unset is **not dispatchable** |
| Pre-dispatch estimate | every compute step passes the estimate gate of §8.2.5 **before** the first container: a numeric ceiling approved for that step, a worst-case estimate at or below it, and a recorded rate source. An unavailable estimate ⇒ **no dispatch** |
| Estimate source | the provider's published rate for the declared resources — an input to the approval record, never a constant in the repository (`benchmarks/adapters.py:19`; `cost_status: "unmeasured"` in the published `summary.json:167`) |
| Actual spend | the provider's own billing report after the run (`benchmarks/run_iteration19_cpu_smoke.py:177-189`), compared with the ceiling; an overrun aborts the step (`modal app stop`) and is recorded as an overrun |
| Per-step approvals | **A-R3**, **A-R3b**, **A-R4** — one per step, each with its own ceiling (§8.2.5). No approval implies another: the approval of R4 approves R4 and nothing else |
| Per-step caps | **exactly 1 attempt** per step, no automatic retry (D20): 1 container / 1 target for R3 (worst case **1** Modal invocation), 1 GPU call and at most **4** Modal invocations for R3b; the 16-target run is one authorised run bounded by the Q5 ceiling (§8.2.5) |
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
| **D14** | **Every compute step has its own hard cap, its own stop condition and its own explicit approval.** No approval implies another, and no approval implies a retry (D20). | A CPU container on Modal is compute, too, and R3b spends GPU credits before the Q5 ceiling is set. A cap that is not fixed before the step starts is not a cap (§8.2.5). |
| **D15** | **The run executes from a detached worktree pinned at the producer commit `P`.** The manifest's `git.commit_sha`, the run directory's suffix, the report's `code_sha` and the closure's capture binding are therefore the same value by construction. | The manifest reads its SHA from the checkout that executes the run, so the risk is not a lying manifest but running from the wrong checkout. A detached worktree is the only arrangement in which the four bindings cannot drift apart (§8.2.6, §9.3). |
| **D16** | **No compute step is dispatched without a pre-dispatch cost estimate at or below its own approved ceiling. If the estimate is unavailable, the step does not start.** The estimate covers the step's **single** attempt (D20); a retry step needs its own estimate against its own ceiling. The three monetary ceilings — R3, R3b, R4 — remain **Q5** (§11.2) and are **not** set by this plan; until they are supplied and approved, all three steps are undispatchable. | A cap that is only checked after the spend is not a gate, and R3b spends GPU credits before the full-run ceiling exists, so it needs a ceiling, an approval and an estimate of its own. The repository deliberately has no cost estimator (`benchmarks/adapters.py:19`; `cost_status: "unmeasured"`), so the estimate has to come from the provider and be recorded with its source — it cannot be invented here (§8.2.5). |
| **D17** | **R3 runs the producer's own `execute_target()` and takes the adapter's candidate-generator branch, so the inference stage is not attempted.** The mechanism is the `candidate_generator` parameter the production adapter already has (`benchmarks/adapters.py:1596`, stored at `:1603`, used at `:1783-1784`) — not a separate smoke app, and not a `modal_cpu` provider, which does not exist in the code. R1 introduces the **fixture and its loader**, not a bypass mechanism. | Only the producer writes the §5 stage block (`benchmarks/adapters.py:2377-2411`); the dedicated CPU app (`benchmarks/modal_cpu_smoke_app.py`) produces a single-function identity record and stays a pre-flight check. The candidate generator short-circuits the provider dispatch **before** the GPU call (`:1783` vs `:1785-1792`), and the refinement loop cannot fire because it requires `candidate_generator is None` (`:1838`), so R3 makes exactly one Modal call, and it is a CPU one. The stage block is always complete — all four keys are written (`:2377-2409`) — so the attempt flag inside it is what distinguishes "not attempted" from "attempted and failed" (`evidence_integrity.py:1829-1836`, `:608-614`) (§8.2.1, §10.2). |
| **D18** | **The producer surface is sealed at `P`, and the run is bound to the bytes of `P`.** Every execution step and every step that judges the run's bytes happens in the detached worktree at `P`; the executed producer bytes are verified by digest; and any commit after `P` that touches a producer path **invalidates the run** and requires a fresh capture. | The manifest's SHA binds a commit; a digest binds the bytes, and only the second one rules out "the code that ran is not the code that was named". A producer-changing commit between the capture and the closure is detected by P6.14's diff, and the consequence is fixed in advance — a new capture, not a re-labelled one (§8.2.6, §9.3). |
| **D19** | **R3's candidate is a checked-in, non-breaching fixture — a negative control — and R3 claims only the EVM-sandbox stage.** The fixture is never presented as model output, is written outside `benchmarks/evidence/`, and its digest is recorded with the smoke. R3 records `independent_replay.attempted = false` and proves nothing about the replay stage. | A plumbing smoke needs a candidate that costs no GPU credits and cannot fabricate a finding. A model candidate would make R3 a paid inference test — that is R3b. A breaching candidate would make the replay branch fire (`adapters.py:1882`) and turn a plumbing smoke into an accidental benchmark run. The producer enters that branch only on `INVARIANT_BREACH_UNREPLAYED`, so a non-breaching fixture keeps the smoke deterministic and its stage matrix fixed (§8.2.1 b, c). |
| **D20** | **Every compute step is a single attempt.** R3 is dispatched exactly once — worst case **1** Modal invocation; R3b exactly once — worst case **4** Modal invocations, all of them inside that one attempt; R4 as one authorised run of its 16 targets. There is **no automatic retry**: a failure ends the step, and a retry is a **new, separately named step** (for example `R3r`, `R3br`, `R4r`) with its own approval, its own ceiling, its own pre-dispatch estimate and its own row in the approval record. | A "1 invocation" description next to a "≤ 2 attempts" cap is not an execution contract but two contradicting ones, and a cap that silently permits a second attempt is a cap with two budgets. Settling the semantics in one place — one attempt per step — keeps the invocation maxima exact (1 and 4, with no hidden second path), keeps the cost ceiling meaningful and keeps the pre-dispatch estimate equal to the worst case (§8.2.1 c, §8.2.2, §8.2.5, §10.3). |

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
| **Q5** | What are the three monetary ceilings — the CPU smoke **R3**, the GPU smoke **R3b** and the 16-target run **R4**? | §10.3, §8.2.5. R3b spends GPU credits *before* R4, so its own ceiling must exist before its approval **A-R3b** is granted; R4's ceiling must exist before **A-R4**; R3 is billed Modal compute too, so it has its own, smaller ceiling before **A-R3**. All three are also the input to the pre-dispatch estimate gate (D16): a step whose ceiling is unset is **not dispatchable**, so this question blocks the whole sequence, not only its paid part. | to be set by the maintainer |
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
6. The negative tests T1–T12 exist, and each was observed to fail against the pre-fix code.
7. `python -m benchmarks.regenerate_billing_join_table --check` → PASSED; the join table is
   still schema 3.0.0 with `aggregate_bucket_allocation: "FORBIDDEN"`; **all 17 harness
   digests match the regenerated harness validation file**; and `source_raw_export.sha256` is
   still `1529b1b9…` unless the raw export was re-exported (§4.4, §7.3).
8. Every validator exits 0 and reports its expected verdict:
   - iterations 14–18 → **`FAILED (0/16)`, unchanged** (D8);
   - the replacement iteration → **`PASSED`** — the expectation fixed in `REPLACEMENT_EVIDENCE`
     before the run was made (§8.2.4 d, §9.4). If the actual validator result is **not**
     `PASSED`, the closure **fails**, the run is **not** accepted as replacement evidence, and
     the actual result is reported honestly — in the replacement report and in the Draft PR of
     R12 — and is never relabelled (D7, D8);
   - iterations 19–23 → `PASSED`; closure → `21/21 PASSED`, with the 14–18 rows of
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
18. Every compute step's approval record contains: the approver, the date, the **numeric**
    ceiling, the pre-dispatch estimate with the rate source it was computed from, and the
    actual spend read back from the provider. No step was dispatched without an estimate at
    or below its ceiling, and no step whose estimate was unavailable was dispatched at all —
    it was recorded as "not dispatched — estimate unavailable" with its reason (D16, §8.2.5,
    Q5).
19. The producer bytes that executed are byte-identical to the producer bytes of `P`: the
    git blob ids and the SHA-256 digests over the LF bytes of `modal_app.py`,
    `benchmarks/adapters.py` and `benchmarks/benchmark_runner.py` match between
    `git show <P>:<path>` and the executing worktree, and that worktree's
    `git status --porcelain` is empty. If any commit after `P` had touched a producer path,
    the run was discarded and a fresh capture was made instead of publishing the invalidated
    one (D18, §8.2.6, §9.3).
20. **The R3 smoke claims only what it exercised.** The smoke artifact records
    `inference.attempted = false`, `evm_sandbox.attempted = true`,
    `independent_replay.attempted = false`, `trajectory_persistence.attempted = false`
    (§8.2.1 c); its candidate is the checked-in fixture of §8.2.1 (b), the digest of that
    fixture is recorded with the smoke, and the artifact lives outside
    `benchmarks/evidence/`. No report, commit message or PR description of the regeneration
    states that R3 exercised the inference stage or the replay stage, and no published file
    refers to the smoke (D17, D19).
21. **The function names agree with the attempts.** A stage that was not attempted records
    `function_name: null`, and `tool_metadata.modal_functions` names exactly the Modal
    functions that were invoked for that target — both derived from the same flags as the
    stage block (`adapters.py:2154-2163`, `:2246-2254` and `:2378-2384` are where this is
    fixed); an artifact that records `inference.attempted = false` may neither list
    `ProductionAuditAgent.generate_solidity_exploit` in `modal_functions` nor name it as the
    stage's `function_name` (§8.2.1 e, item 7).
22. **"Not attempted" and "attempted and failed" are not interchangeable.** Every stage's
    `attempted` flag agrees with the absence kind its identity facts carry: a stage with
    `attempted: false` carries `STAGE_NOT_ATTEMPTED` and nothing else, and a stage with
    `attempted: true` carries none (C6, T12, §8.2.1 d).
23. **Every compute step was dispatched exactly once.** R3 made exactly **1** Modal
    invocation; R3b at most **4**, all of them inside its single attempt; R4 was one
    authorised run of its 16 targets. No step was retried automatically: a step that failed
    ended there with the failure recorded, and any retry appears as a **separately named
    step** with its own approval, its own ceiling, its own pre-dispatch estimate and its own
    row in the approval record of the PR (D20, §8.2.5, §10.3).

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
  specification, not a budget that was spent. No step was dispatched, no step was retried and
  no retry step was created (D20).
* No cost estimate was computed for any step and no provider rate was read: the
  pre-dispatch estimate gate (D16, §8.2.5) is specified, not exercised. The numeric
  ceilings of R3, R3b and R4 remain unresolved (**Q5**), so none of the three steps is
  dispatchable.
* No producer commit `P` was created, no worktree was pinned, and no producer byte was
  digest-verified (§8.2.6, D18): the producer surface is still open.
* No run was executed from the detached worktree at `P` (§8.2.6): the producer commit `P` does
  not exist yet — it is sealed after R1 and R2 of a future, separately authorised iteration.
* No published digest was re-computed into a record.
* The historical FAILED (0/16) results of Iterations 14–18 were not rewritten, and the run
  directory they were computed from was not modified, moved or deleted (D8, D9).
* PR #12 and PR #13 were not merged, re-based, closed or modified; their base branches and
  `main` were not touched.
* No branch was force-pushed and no published branch had its history rewritten (D11).
* The only file changed by this iteration is this document — no code, no evidence, no
  validator, no schema, no report.
