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
Six findings changed the shape of the plan; they are stated first because they invalidate
two premises of the task.

| # | Finding | Consequence for the plan |
|---|---|---|
| **F1** | The pseudo-URI inventory is **165**, not 99 — and not 132. The 99 of the task counts only two of the four files that carry the URIs; a script that scans a single run directory counts 132 and misses the root-level `latest_summary.json` (§2). | The inventory in §2 enumerates all 165 occurrences, by file, JSON path and value, over the **whole** tracked artifacts tree. |
| **F2** | The current validator **already rejects** the published pseudo-URIs — but for a *different, earlier* reason than the URI. Iterations 14–18 fail on `missing 'function_call_id'` and `missing 'image_digest'`, i.e. the URI check is never reached (§4.2). | The regeneration cannot be "clean up the URI"; it must **replace the whole provenance schema** of the artifacts, because the schema the URI lives in is itself rejected. |
| **F3** | The upstream bytes are **not** a drop-in replacement. Upstream's rewritten artifacts still fail the iteration-line validators, and they introduce a *new* defect: a synthetic `container_id` of the exact shape the validator forbids (§3.2). | The upstream bytes cannot be taken as-is. §5 specifies a third contract: iteration-line schema **+** upstream's `NOT_AVAILABLE` honesty **+** upstream's field rename, with the upstream defects fixed. |
| **F4** | `has_synthetic_modal_uri` is **not enforced** on the authoritative paths. In Iterations 14–16 it is recorded as a diagnostic field (`synthetic_uri_present`) next to a billing check whose verdict it does not influence; Iterations 17–23 and the closure validator do not call it at all (§4.3). | §6 specifies the exact call-path changes needed to make the detector authoritative, plus the negative tests that prove it. |
| **F5** | The SHA-256 pins **do** bind the 16 target artifacts. `reproducibility_manifest.json → adapters.baseline_5.artifact_files` carries 48 `(relative_path, size_bytes, sha256)` records — 16 target JSONs + 32 stdout/stderr files — and all 16 JSON digests match the git blob bytes (§7.2). | The blast radius of a regeneration is **wider** than the task assumes: regenerating the target artifacts forces a re-pin of the manifest, and the manifest and the harness validation already disagree on 15 of the 32 stdout digests because they were computed over different line-ending conventions (§7.3). |
| **F6** | The producer makes **up to six** Modal calls per target, not four — and the published bytes prove it. The adapter refines a failed candidate once and verifies it again (`benchmarks/adapters.py:1830-1871`, `:1866`); **14 of the 16** published artifacts record `candidates_generated = 2`, so the branch fired in the published run itself — while their `tool_metadata.modal_functions` name only **two** functions per refined target (§5.6). | The invocation caps of R3b and R4 were under-specified, and the stage block cannot represent a stage that ran twice. §5.6 specifies the six stage keys, the per-target invocation trace and the producer fixes that bind each stage's facts to the call that produced them; §8.2.5 turns that trace into the exact counts the cost estimate refers to. |

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

**The stage set has six keys, not four.** The producer's closed-loop refinement makes a
second GPU call and a second CPU verification of the same target (§5.6), so a stage block
that carries one identity triple can no longer say *which* call its facts belong to. The six
keys are `inference`, `evm_sandbox`, `refinement`, `evm_sandbox_after_refinement`,
`independent_replay` and `trajectory_persistence` — **all six always present**, in pipeline
order, each with its own `attempted` flag, exactly as the four existing keys already behave
(`benchmarks/adapters.py:2377-2409`). §5.6 specifies them, the producer changes that
produce them, and the defect in the current producer that they repair.

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

### 5.6 The refinement branch: the invocation trace, the six stage keys, the producer defect

The producer does not make one inference call per target. It makes **one or two**, and the
second one is a *different Modal function*. This section is the plan's answer to the P0
review of [issuecomment-6798979826](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/14#issuecomment-6798979826),
which found the invocation caps of R3b and R4 to be under-specified.

#### (a) What the code does

At `benchmarks/adapters.py:1830-1871` the adapter runs a closed-loop refinement:

| # | Call | Modal function | Resource class | Source | Dispatched when |
|---|---|---|---|---|---|
| 1 | the inference | `ProductionAuditAgent.generate_solidity_exploit` | **GPU** (H100) | `:1785-1792` | always (the `modal_h100` branch) |
| 2 | the first verification | `verify_exploit_remote` | **sandbox CPU** — request `config.SANDBOX_CPU_CORES` (2.0 cores) / `config.SANDBOX_MEMORY_MB` (2048 MiB); a request is not a cap (§5.6 g) | `:1826` | always |
| 3 | the refinement | `ProductionAuditAgent.refine_solidity_exploit` | **GPU** (H100) | `:1844-1851` | the first verdict is neither `INVARIANT_BREACH_UNREPLAYED` nor `EXPLOIT_CONFIRMED`, the candidate is non-empty, **no** `candidate_generator` is injected and the provider is `modal_h100` or `modal_t4` (`:1833-1840`) |
| 4 | the second verification | `verify_exploit_remote` | **sandbox CPU** — request 2.0 cores / 2048 MiB (§5.6 g) | `:1860-1867` | the refinement returned a usable payload (`test_code` longer than 20 characters) |
| 5 | the replay | `verify_replay_remote` | **sandbox CPU** — request 2.0 cores / 2048 MiB (§5.6 g) | `:1873-1885` | the **final** verdict is `INVARIANT_BREACH_UNREPLAYED` (`:1882`) |
| 6 | the persistence | `record_trajectory_remote` | **persistence function** — *its own* profile: **no** `cpu=` and **no** `memory=` (request 0.125 cores / 128 MiB, default CPU limit 16.125 cores, no hard memory limit), a persistent volume at `/vol/models`, `timeout=60`; billed over the container's lifetime — startup + execution + idle (§5.6 g) | `:2128-2145` | `is_verified`, i.e. the replay confirmed the breach (`:2104-2109`, `:2133`) |

`max_refinements = 1` (`:1831`), so a target makes **at most one** refinement: there is no
seventh call. The loop swallows every exception and breaks (`:1870-1871`), so a failed
refinement or a failed second verification ends the branch without adding a call.

**Therefore: at most six Modal calls per target — 2 GPU + 3 sandbox-CPU + 1 persistence
function.** These are **invocation** counts; a container may serve several invocations, so the
invocation count is an upper bound on the number of containers (§5.6 g, D27). The persistence
call is **not** a sandbox-CPU call and is **not** a free volume operation: it is a container of
its own, with its own resource profile, and it is billed as compute (§5.6 g). §8.2.5 turns
this trace into the exact counts of the compute steps.

#### (b) The branch fired in the published run, and the published provenance under-reports it

`candidates_generated` is incremented in exactly one place of the production adapter: inside
the refinement branch, after a refined payload has been accepted (`:1862`; the same code
stands at the published run's commit `70f5d22` — `benchmarks/adapters.py:1508-1545`). The
published artifacts therefore **measure** the branch:

```
$ python - <<'PY'
import json, subprocess
files = subprocess.check_output(
    ["git", "ls-files", "benchmarks/artifacts/run_1794209615_70f5d22/baseline_5"]
).decode().split()
for f in sorted(files):
    if not f.endswith(".json"):
        continue
    d = json.loads(subprocess.check_output(["git", "show", "HEAD:" + f]))
    print(d["target_id"], d["candidates_generated"],
          ",".join(d["tool_metadata"]["modal_functions"]))
PY
```

| Published artifacts | `candidates_generated` | What that proves | Modal calls actually made | Resource classes of those calls |
|---|---|---|---|---|
| 14 of 16 — `BIZ-01`, `BRIDGE-01`, `DOS-01`, `ERC4626-01`, `FLASH-01`, `LIQ-01`, `ORACLE-01`, `PREC-01`, `SAFE-01`, `SAFE-02`, `SAFE-03`, `SAFE-04`, `SIG-01`, `STATE-01` | **2** | the refinement fired and the refined candidate was **dispatched for a second verification** | **4**: generate, verify, refine, verify | **2 GPU + 2 sandbox-CPU** |
| 2 of 16 — `AC-01`, `REENT-01` | **1** | the first candidate breached, the loop was never entered | **4**: generate, verify, replay, persist | **1 GPU + 2 sandbox-CPU + 1 persistence function** |

Every published target therefore made **four** Modal calls — **64** in the run. Split by
resource class, that is **30 GPU + 32 sandbox-CPU + 2 persistence-function** invocations:
14 × (2 GPU + 2 sandbox-CPU) = 28 GPU + 28 sandbox-CPU, plus 2 × (1 GPU + 1 sandbox-CPU
verify + 1 sandbox-CPU replay + 1 persistence) = 2 GPU + 4 sandbox-CPU + 2 persistence.

**The 2 persistence calls are neither sandbox-CPU calls nor zero-cost volume operations:**
each is a container of its own, with its own resource profile and its own compute charge
(§5.6 g). The published `tool_metadata.modal_functions`, however, name **two** functions for
each of the 14 refined targets and **four** for the two confirmed ones: the refinement and the
second verification are missing from all 14 refined artifacts.

**This is a second instance of the defect the plan exists to fix.** The function list is
derived from the **provider** and the stage flags (`adapters.py:2154-2163`), not from the
calls that actually happened — so the published bytes under-report their own execution trace,
and they do it on 14 of 16 targets. The `modal_functions` fix of §8.2.1 (e) is therefore not
only about the four stage flags: it must cover the refinement branch as well (C8, §6.5).

#### (c) Under refinement, two stages carry the *wrong* call's facts

This is worse than an under-report. When the refinement fires, the producer **overwrites**
the captures of the two earlier stages:

* `inference_response = rp_dict` (`:1863`) replaces the initial inference's response with the
  **refinement's** response. The runtime envelope is read from that same variable
  (`:2238-2242`), so the `inference` stage — whose `function_name` is
  `ProductionAuditAgent.generate_solidity_exploit` (`:2246-2254`, `:2378-2384`) — ends up
  carrying the **refinement call's** `app_id`, `function_call_id`, `container_id` and payload;
* `verdict_dict = verify_exploit_remote.remote(...)` (`:1866`) replaces the first
  verification's response with the **second** verification's. `evm_runtime` (`:2233`) and the
  run-level `remote_evm_provenance` (`:2202-2206`) are read from that variable, so the
  `evm_sandbox` stage carries the second call's facts and the **first** verification's
  response and identity are lost from the artifact altogether.

A stage that names one function and carries another function's identity facts is a **false
provenance statement** — precisely what §5.1's contract exists to prevent. It is invisible
in the published bytes only because those bytes are rejected for other reasons first (F2).

#### (d) The six stage keys

| # | Stage key | Function | Resource class | `attempted: true` when |
|---|---|---|---|---|
| 1 | `inference` | `ProductionAuditAgent.generate_solidity_exploit` | GPU (H100) | always (the provider branch) |
| 2 | `evm_sandbox` | `verify_exploit_remote` | sandbox CPU — request 2.0 cores / 2048 MiB (§5.6 g) | always (the first verification) |
| 3 | `refinement` | `ProductionAuditAgent.refine_solidity_exploit` | GPU (H100) | the loop was entered (§5.6 (a), call 3) |
| 4 | `evm_sandbox_after_refinement` | `verify_exploit_remote` | sandbox CPU — request 2.0 cores / 2048 MiB (§5.6 g) | the refinement returned a usable payload (call 4) |
| 5 | `independent_replay` | `verify_replay_remote` | sandbox CPU — request 2.0 cores / 2048 MiB (§5.6 g) | the final verdict is `INVARIANT_BREACH_UNREPLAYED` (call 5) |
| 6 | `trajectory_persistence` | `record_trajectory_remote` | persistence function — no `cpu=`/`memory=` declared: request 0.125 cores / 128 MiB, default CPU limit 16.125 cores, no hard memory limit, `timeout=60`, persistent volume attached (§5.6 g) | the replay confirmed the breach (call 6) |

The keys are written in **pipeline order**, all six are always present, and `attempted` is
derived from the capture — exactly the rule the four existing keys already follow
(`adapters.py:2377-2409`). `MODAL_PROVENANCE_STAGES` (`evidence_integrity.py:1806`) is
defined once and referenced nowhere, so no validator constrains the stage set and no
existing code has to be taught about the two new keys.

The producer work that R1 does (implementation, not this plan):

1. **Stop overwriting the captures.** `inference_response` keeps the initial inference's
   response; the refinement's response goes into a new `refinement_response`; the first
   verification's response and verdict are kept beside the final ones. Each stage's facts
   are then derived from *its own* capture, and the mis-attribution of §5.6 (c) disappears.
2. **Add the two captures** to `stage_captures` (`adapters.py:2259-2308`). The evidence
   artifacts are written by the loop that already exists (`:2346-2353`), so the two new
   stages get their own evidence artifacts without a new mechanism.
3. **Bind the function name to the capture.** `StageResponseCapture`
   (`evidence_integrity.py:1019-1042`) has no function-name field today; the stage's
   `function_name` is passed separately to `build_modal_stage_provenance` (`:1809-1818`) and
   comes from the provider (`:2246-2254`). R1 adds the field, so that the name and the facts
   of a stage come from **one** source, and the stage's own evidence artifact records the
   name of the call it holds. C7 makes that checkable from the bytes alone.
4. **Derive `modal_functions` from the captures**, in dispatch order (C8, §6.5).

#### (e) The run-level remote-EVM block and the second verification

The run-level `remote_evm_provenance` block (§5.4) describes **one** EVM verification. After
the change it describes the **final** one — the verification whose verdict the artifact
publishes — and the first verification's environment stays recoverable in the `evm_sandbox`
stage's own evidence artifact, which holds the exact bytes that call returned
(`write_stage_evidence_artifact`, `evidence_integrity.py:1271-1300`). The plan does not
duplicate the eight facts into a second run-level block: one published verdict, one
describing block, and every call's own bytes in its own stage artifact.

#### (f) What this costs and what it does not cost

Nothing here was measured on a live provider. The facts of this section come from **reading
the producer source** at the baseline commit and at the published run's commit `70f5d22`, and
from **reading the published artifacts' own bytes** (`candidates_generated`,
`tool_metadata.modal_functions`). No Modal call, no deployment, no GPU allocation and no
credit spend were involved (§12).

#### (g) The resource profiles: request ≠ limit ≠ actual, and the billable lifetime of a container

Three Modal resource classes are dispatched by the trace of §5.6 (a) — **sandbox CPU**, **GPU
(H100)** and the **persistence function**. Each is a container of its own, and each has three
distinct numbers that this plan keeps apart: the **request** (what the container is
guaranteed), the **limit** (the highest usage the provider enforces) and the **actual usage**
(what the container really consumed). Modal bills **the higher of request and actual usage**,
per second — so a request is a **floor** on the bill, never a cap on it.

**What the repository declares today** (read from the source; nothing was measured on a live
provider):

| Class | Functions | CPU request | CPU limit (enforced) | Memory request | Memory limit (enforced) | Execution timeout | Startup bound | Idle-retention bound |
|---|---|---|---|---|---|---|---|---|
| **sandbox CPU** | `verify_exploit_remote`, `verify_replay_remote` (`modal_app.py:550-556`, `:582-588`) | **2.0 cores** — `cpu=config.SANDBOX_CPU_CORES` (`core/config.py:37`) | **18.0 cores** — the default limit is *request + 16*, enforced by host throttling | **2048 MiB** — `memory=config.SANDBOX_MEMORY_MB` (`core/config.py:38`) | **none** — a scalar `memory=` is a request, not a hard limit | `timeout=60` (`config.SANDBOX_TIMEOUT_SEC`) | **60 s** — with no `startup_timeout`, `timeout` configures the startup as well | **60 s** — the default `scaledown_window` |
| **GPU (H100)** | `ProductionAuditAgent.generate_solidity_exploit`, `.refine_solidity_exploit` (`modal_app.py:74-80`) | **0.125 cores** — no `cpu=` is declared | **16.125 cores** (default = request + 16), throttled | **128 MiB** — no `memory=` is declared | **none** | `timeout=1200` | **1200 s** (no `startup_timeout`) | **60 s** |
| **persistence function** | `record_trajectory_remote` (`modal_app.py:695-700`) | **0.125 cores** — no `cpu=` is declared | **16.125 cores**, throttled | **128 MiB** — no `memory=` is declared | **none** | `timeout=60` | **60 s** | **60 s** |

**What the repository proves.** At `modal_app.py:695-700` the persistence function is declared as

```python
@app.function(
    image=sandbox_image,
    volumes={"/vol/models": model_volume},
    timeout=60,
)
def record_trajectory_remote(trajectory_dict: dict) -> str:
```

It carries **no** `cpu=` and **no** `memory=` argument. It is therefore *not* the
`cpu=config.SANDBOX_CPU_CORES` / `memory=config.SANDBOX_MEMORY_MB` profile of
`verify_exploit_remote` and `verify_replay_remote` (`modal_app.py:550-556`, `:582-588`;
`core/config.py:37-38` — a **2.0-core / 2048 MiB request**). It has its own `timeout=60`, and
it **commits the persistent volume** (`:709-711`, inside a `try/except` that swallows the
failure). The commit is I/O against the volume; the volume's **storage** is billed separately
from the container's **compute** (the table below).

**What the provider's own documentation adds.** For a Modal Function with no explicit
resource request, the platform default is:

| Property | Value | Source |
|---|---|---|
| Default CPU **request** | **0.125 physical cores** | Modal Docs, *Configuring CPU, memory, and disk* — "Each Modal Function or Sandbox container has a default request of 0.125 CPU cores and 128 MiB of memory" (https://modal.com/docs/guide/resources) |
| Default memory **request** | **128 MiB** | same |
| A request is **not** a cap | "**Containers can exceed this minimum** if the worker has available CPU or memory" | same |
| Default CPU **limit** | **request + 16 physical cores**, enforced by throttling — 16.125 cores at the default request, **18.0 cores at the sandbox's 2.0-core request** | same — "Modal containers have a default CPU limit that is set at 16 physical cores above the CPU request… The host enforces this limit by throttling the container's CPU usage so it cannot exceed the limit" |
| Explicit CPU limit | `cpu=(cpu_request, cpu_limit)` | same — "You can alternatively set the CPU limit explicitly" |
| Memory limit | **only** via `memory=(mem_request, mem_limit)` — a hard limit that OOM-kills the container. **A scalar `memory=` sets no limit at all** | same — "Modal containers can have a hard memory limit which will 'Out of Memory' (OOM) kill containers which attempt to exceed the limit… Specify this limit using the `memory` parameter" |
| Billing basis | **max(request, actual usage)**, per second | same — "For CPU and memory, you'll be charged based on whichever is higher: your request or actual usage" |
| Core semantics | 1 physical core = 2 vCPUs | Modal Docs / pricing FAQ |
| Rate class | the **base list price** — Functions are preemptible by default; the 3× non-preemptible multiplier applies to Sandboxes, not to these `@app.function` targets | Modal pricing FAQ (https://modal.com/pricing) |
| Billable phases | **load time + processing time + the idle retention** — "Modal bills you during application load time and during the time your container is processing inputs. By default, we keep containers alive for 60 seconds after the last inputs before we shut them down, **which we also bill for**" | Modal pricing FAQ |
| Container idle time | **60 s by default**, configurable through `scaledown_window` (2 s … 20 min) | Modal Docs, *Cold start performance* — "By default, the maximum idle time is 60 seconds. You can configure this by setting the `scaledown_window`"; *Scaling out* — "the maximum duration (in seconds) that individual containers can remain idle when scaling down" |
| Autoscaler settings | four provider-enforced knobs — `max_containers` ("The upper limit on containers for the specific Function"), `min_containers` ("The minimum number of containers that should be kept warm, **even when the Function is inactive**"), `buffer_containers` ("The size of the buffer to maintain while the Function is active") and `scaledown_window` ("The maximum duration (in seconds) that individual containers can remain idle when scaling down"). **The repository declares none of them today.** | Modal Docs, *Scaling out* (https://modal.com/docs/guide/scale); the SDK reference gives the same four as `min_containers` — "Minimum number of containers to keep running regardless of demand", `max_containers` — "Limit on the number of containers that can be concurrently running", `buffer_containers` — "Extra containers to scale up beyond current demand", `scaledown_window` — "Maximum duration (in seconds) idle containers wait before scaling down" (https://modal.com/docs/sdk/py/latest/modal.App) |
| Dynamic autoscaler updates | the settings can be changed **at runtime, without a redeploy** — and they revert to the decorator's values on the next deployment | Modal Docs, *Scaling out* — "It's also possible to view and update the autoscaler settings dynamically (i.e., without redeploying the App) using the `Function.autoscaler.update()` method" and "The autoscaler settings will revert to the configuration in the function decorator the next time you deploy the App" |
| Platform concurrency limits | a hard limit of **4,000** concurrent containers for a single Function; the workspace's plan level caps the total concurrent containers and the concurrent GPUs ("100 containers + 10 GPU concurrency" on Starter, "5000 containers + 50 GPU concurrency" on Team) | Modal Docs, *Scaling out*, *Scaling Limits*; Modal pricing, *Pricing plans* |
| Network egress | its **own rate class**, separate from compute: a per-GiB price with a plan-dependent monthly allowance ("*See plan for included usage / mo*" — 1 TiB/month free on Starter, 10 TiB/month free on Team). The per-GiB price itself is an **approval input**, never a constant of this document (§8.2.5, input 9) | Modal pricing (https://modal.com/pricing, read 2026-11-11) |
| Persistent volume | its own **storage** rate — a per-GiB-month price, separate from compute, with a published free allowance of **1 TiB/month**. The provider publishes **no separate commit fee**: a `commit()` is I/O against the volume, not a priced event | Modal pricing (https://modal.com/pricing, read 2026-11-11) — "Volumes … *includes 1 TiB / mo free*"; the free allowance is a provider fact, the per-GiB price is an approval input (§8.2.5, input 8) |

**Two consequences that the cost model must respect.**

1. **A request is a floor, not a ceiling.** The sandbox functions' `cpu=2.0` is a request; with
   the documented default limit rule their enforced CPU ceiling is **18.0 physical cores**, not
   2.0. Their `memory=2048` is a request as well, and **no** hard memory limit exists today —
   the container may exceed 2048 MiB, and nothing in the provider's defaults stops it. The same
   holds for the GPU containers: `ProductionAuditAgent` is declared (`modal_app.py:74-80`) with
   `gpu=config.AUDIT_GPU_TYPE` and **no** `cpu=`, so the H100 line and the CPU/Memory lines are
   **separate charges on the same container**, not one number — and its memory is unbounded too.
2. **The billable lifetime is the container's, not the function's.** Modal's timeout is an
   **execution** timeout: "The timeout duration is a measure of a Function's **execution time**.
   It does not include scheduling time or any other period besides the time your code is
   executing in Modal" (Modal Docs, *Timeouts*). The container's startup is a separate phase,
   bounded by `startup_timeout` — and, when `startup_timeout` is **not** set, "**`timeout` will
   still configure both times**" (same page). After the last input the container is kept alive
   for the idle window, and that time is billed too (pricing FAQ above). The billable seconds of
   one container are therefore

   ```
   T_billable = T_startup + T_execution + T_idle
   ```

   and with the declarations of today they are `60 + 60 + 60 = 180 s` for the sandbox and the
   persistence functions and `1200 + 1200 + 60 = 2460 s` for the GPU container. A `timeout=60`
   is **not** a 60-second bill, and it is not a 60-second minimum charge either.

**Invocations are not containers.** "Modal will reuse the same container for multiple inputs"
(Modal Docs, *Container lifecycle hooks*). The number of **invocations** of a step is therefore
an **upper bound** on the number of **containers** it starts — never an equality. The worst
case for an estimate is one container per invocation; the real container count is a fact that
only the provider's own report knows. The invocation counts of §8.2.5 stay exactly as they are:
they count **calls**, and they are used as the conservative container bound.

**That bound is only as good as the autoscaler policy — and the repository declares none.**
The invocation bound says *every billed container serves at least one invocation*. The provider
is free to break it: `min_containers` keeps containers warm "even when the Function is
inactive", and `buffer_containers` maintains an idle buffer "while the Function is active"
(Modal Docs, *Scaling out*) — both are billed during the step without carrying a single
invocation. The repository declares **none** of the four knobs today, and the provider's
documentation states **no default** for `min_containers` / `buffer_containers`, so an unset
autoscaler setting is an unknown in exactly the same way an unset memory limit is (an unset
memory limit has no ceiling at all — *Containers can exceed this minimum*, Modal Docs,
*Configuring CPU, memory, and disk*). The invocation bound therefore holds **only** once R1
declares `min_containers=0` and `buffer_containers=0`; §8.2.5 specifies that policy, the
deployed `max_containers` ceiling that never changes between the steps, the per-step caps the
**dispatch helper** enforces, and the read-back that proves the deployed settings are the
approved ones (D27). `max_containers` adds a second, independent provider-enforced bound —
the **concurrency** of a class — and the workspace's own plan-level limits (100 containers +
10 GPU concurrency on Starter, 5000 containers + 50 GPU concurrency on Team) can only *lower*
the number of containers billed **simultaneously**; they never raise the total above the
invocation count.

**Therefore the persistence call is a real, billable compute call.** It is not free, and it is
not the sandbox's profile: it is a container of its own, on the platform default request
(0.125 cores / 128 MiB), billed on `max(request, actual usage)`, with the volume's storage
billed on top. **There is no separate "persistence" rate class** — the provider publishes CPU
and memory rates by resource class, and the persistence function is a Function, so it is priced
with the **same** Function CPU and memory rates as the other Functions plus the volume's
storage rate (D25).

**What the repository's billing data can and cannot resolve.** The published raw export
(`benchmarks/evidence/modal_billing_report_raw.json`) is aggregated **per app session**: each
of its 25 line items is `{object_id (app id), description (app name), environment,
interval_start, resource, cost}`, and `resource` is one of `CPU`, `Memory`, `H100`,
`Network Egress`. **There is no function-level dimension in it.** For the canonical run's app
session (`ap-EDUitOwWeMrIdYbTh4kB63`, `aegis-rlvr-security`, `2026-11-09`) the measured line
items are exactly four: `H100 $0.74323683`, `CPU $0.03001687`, `Memory $0.00696753`,
`Network Egress $2.6E-7`. The **$0.03001687 CPU line is the aggregate of every CPU-bearing
container in that app session** — the 30 GPU containers' own CPU, the 32 sandbox-CPU calls and
the 2 persistence calls alike. The published evidence therefore **cannot** attribute the
persistence function's own share of it, nor anyone else's.

That share is an **unresolved historical attribution** — it can only be established by the
provider's per-function usage data, or by a measurement (one dispatched persistence call, read
back from the provider's own billing report). **It is not a missing price.** The rate that
prices the persistence function is the published Function CPU rate, and it is known; what is
unknown is how the *old* aggregate bill splits across the functions — and nothing in this plan
needs that split, because the published evidence publishes the **app-session total**, the only
level the provider's export resolves (§4.4, §10.3). The two statements are kept apart on
purpose: an unresolved *attribution* is a historical limitation of the published evidence, an
unresolved *bound* is a blocker of the dispatch (§8.2.5, D26–D29).

*Nothing in this subsection was measured on a live provider.* Its facts come from reading
`modal_app.py` and `core/config.py`, from reading the published raw billing export's own
bytes, and from the provider's own published documentation, quoted above with its URL.

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
| **C7** | Bind a stage's `function_name` to the stage's own evidence artifact: the artifact records the name of the function whose call it holds, and the validator refuses a target artifact whose stage names a function the artifact does not. | `evidence_integrity.py::validate_modal_invocation_provenance` (+ `StageResponseCapture`, `build_stage_evidence_artifact`) | today the stage's name is taken from the **provider** (`adapters.py:2246-2254`) while its facts are taken from a capture that may hold a **different** call's response (§5.6 c) — the name and the facts can disagree, and nothing checks it |
| **C8** | Make `tool_metadata.modal_functions` the **ordered invocation trace**: the functions actually invoked for that target, in dispatch order, one entry per call — so the second `verify_exploit_remote` appears **twice**. The validator reconstructs the trace from the stage blocks and compares it with the list. | `evidence_integrity.py::validate_modal_invocation_provenance` (+ `adapters.py:2154-2163`) | the list is built from the provider and the flags, so it names calls that were never made and omits calls that were (§5.6 b) — 14 of the 16 published artifacts under-report their own trace, and on those 14 the `inference` stage names a function whose call the artifact's own facts do not corroborate (§5.6 c) |

### 6.6 Required negative tests

Each of these must fail **before** the fix and pass **after** — with one exception: **T16** is
the positive counterpart of **T13** and passes only *after* the fix, because it asserts a
behaviour (the six-key stage set and the trace-derived function list) that does not exist yet.

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
| **T13** | the **R3b mode cannot dispatch a refinement**: in the producer's R3b configuration `ProductionAuditAgent.refine_solidity_exploit` is never called, and the artifact's `modal_functions` never names it | D22 — R3b's cap of 4 is a property of the R1 producer, not of today's code (§8.2.2 a) |
| **T14** | the function list equals the **invocation trace**: an artifact of a refined target names `ProductionAuditAgent.refine_solidity_exploit` and lists `verify_exploit_remote` **twice**, in dispatch order; an artifact whose list omits a dispatched function, or names one that was never dispatched, is FAILED | C8 — acceptance criterion 21 extended to the refinement branch (§5.6 b) |
| **T15** | a stage's `function_name` and its identity facts belong to the **same** call: an artifact whose `inference` stage carries the `function_call_id` of a `refine_solidity_exploit` call is FAILED | C7 — the mis-attribution defect of §5.6 (c) |
| **T16** | the **mocked six-call trace**: with the Modal calls stubbed, the producer produces the six stage blocks of §5.6 (d) with the right `attempted` flags (`refinement` and `evm_sandbox_after_refinement` `true`, the rest as the verdict dictates) and a trace-derived `modal_functions` of six entries in dispatch order | the refinement branch is covered **at no cost** — the positive counterpart of T13, and the only coverage of the refinement provenance before R4 |

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
   the compute steps are open question **Q5** (§11.2), still unanswered; the CPU smoke
   has its own, smaller ceiling. **No** step starts without its own ceiling, its own
   approval and its own estimate: an approval for R4 approves R4 and nothing else. While Q5
   is unanswered, R2p, R3, R3b and R4 are **not dispatchable at all** — they are not "cheap enough
   to try", they are undefined. Every step also declares its own **wall-clock budget** and
   its own **post-execution deadline**, which are the second and third bounds on the storage
   duration (D28) — **R4 declares neither today**, which is itself a blocker. Independently
   of Q5, the **R1 resource precondition** of
   §8.2.5 must hold: the explicit request/limit pairs and the explicit lifecycle bounds that
   make the estimate a worst case rather than an open-ended quantity (D26). Without them the
   estimate is unbounded and **no** step is dispatchable either.
6. **One dispatch per step.** Every compute step is a **single attempt** (D20): it is
   dispatched once, it is never retried automatically, and a retry is a new, separately named
   step with its own ceiling, its own approval and its own pre-dispatch estimate.
7. A **detached worktree** pinned at the producer commit `P` for the execution steps R3, R3b
   and R4 **and for the steps that judge their bytes (R5, R9)** (§8.2.6), so that the
   manifest, the run directory, the report and the closure all carry the same SHA.
8. The **autoscaler policy** of §8.2.5 (D27) must be deployed and verified before the first
   container: `min_containers=0` and `buffer_containers=0` for every container class, and a
   deployed `max_containers` equal to the **union** of the steps' caps for that class (48 /
   32 / 16) — never lowered and never raised at runtime, with the per-step cap enforced by the
   dispatch helper, and used **only** as a concurrency ceiling: it never clamps a cumulative
   quantity (D29). Without it the estimate's container bound is an arithmetic hope, not a
   provider-enforced fact, and the step is **not dispatchable**.
9. The **volume state** of §8.2.5 (D28) must be known before the first container: the
   baseline of `aegis-model-cache` **measured**, the incremental cap fixed in R1, the
   **storage duration bounded** (the step's wall-clock budget, the ceiling, **and the
   post-execution deadline before the publication**) and the
   retention/cleanup rule scheduled. An unmeasurable volume and an unbounded duration — of the
   execution or of the post-execution interval — are both
   fail-closed stops, not permissive defaults.
10. The **egress policy** of §8.2.5 (D29) must be established per container class before the
    first container: a provider-enforced zero where the class needs no network, a
    **per-container** bound where it does — the GPU class' model download is priced to the
    **prefetch step R2p**, not to the run steps — and the provider's own `Network Egress` line
    as the **post-run audit** of that bound, never as its substitute. The caps are summed over
    the step's **cold containers**, whose count is bounded by the **invocation count** and
    **not** by the concurrency ceiling, and the per-container protocol allowance applies to
    every container, including the GPU class' offline ones. A class whose egress
    cannot be bounded makes the estimate unavailable, and the step is **not dispatchable**.
11. The **prefetch step R2p** must have completed and its cache must have been **verified**
    against the pinned revision's file manifest before R3b or R4 is dispatched: the GPU
    containers run with `local_files_only=True` and refuse to start on an incomplete cache, so
    an unprepared cache is a failed container, not a download (D29).

### 8.2 The sequence

Each step is atomic: it either completes and is committed, or the tree is rolled back to
the last committed step (§8.4).

| Step | Action | Produces | Gate before proceeding |
|---|---|---|---|
| **R0** | Branch `iter-24/evidence-regeneration` from the authorised base. | — | clean tree, base SHA recorded |
| **R1** | Implement the §5 schema in the producer (`adapters.py`, `modal_app.py`, `benchmark_runner.py`), the §6.5 validator changes (**C1–C6**, **C7**, **C8**), the `modal_functions` fix of §8.2.1 (e) — the function list must be derived from the attempts, not from the provider — the **refinement work of §5.6 (d)**: the two additional stage captures, the six stage keys, the function name bound to its capture, the trace-derived `modal_functions`, and the **refinement switch of §8.2.2 (a)** — and the R3 fixture **plus its loader** of §8.2.1 (b) — and the **resource profiles of §8.2.5**: an explicit `cpu=(request, limit)` and `memory=(request, limit)` pair, an explicit `startup_timeout` and an explicit `scaledown_window` for each of the three container classes — the sandbox functions, the GPU class and the persistence function (D26), without which the estimate of §8.2.5 has no upper bound and no compute step is dispatchable — and the **autoscaler policy of §8.2.5 (D27)**: `min_containers=0`, `buffer_containers=0` and a deployed `max_containers` per class equal to the **union** of the steps' caps, with **no** mutating autoscaler call anywhere in the repository — and the **dispatch helper of §8.2.5 (D27)**: the single path through which a Modal call is dispatched, enforcing the per-step **invocation budget**, the **concurrency gate** and the **ceiling assertion**, and reading the effective settings back with the **no-argument** `update_autoscaler()` — and the **egress policy of §8.2.5 (D29)**: a network-blocking declaration for the sandbox class, the **prefetch function** of R2p, `local_files_only=True` plus the offline environment and the cache-manifest check in the GPU class' `@modal.enter()`, the per-container caps and the protocol allowance, summed over the step's cold containers whose count is bounded by the **invocation count** and never clamped by the concurrency ceiling, and the provider's `Network Egress` line as the **post-run audit** — and the **volume policy of §8.2.5 (D28)**: a hard byte cap on the trajectory write of the persistence function, the **wall-clock budget** and the **post-execution deadline** each step declares, and the cleanup helper that removes the run's own files from `aegis-model-cache` and re-measures the volume. | code only | unit tests green; **no** published file touched; R1 does **not** yet seal the producer commit `P` — R2 does |
| **R2** | Add the §6.6 negative tests T1–T16. | tests | each test fails on the pre-fix code and passes on the post-fix code (proven by running both revisions; **T16** is the one positive test and passes only after the fix); **R2 seals the producer commit `P`** — `P` is the commit that closes the producer surface, it is sealed *before* the first container is dispatched, and no commit after it may touch a producer path (§8.2.6, §9.3, D18) |
| **R2p** | **Model-cache prefetch** — populate the volume's model cache **once**, before any GPU step: **one CPU container** (no GPU), one attempt, the **pinned revision** (a commit SHA, not a branch name) of `qtum/Qwen3-Coder-30B-A3B-Audit` downloaded into `/vol/models/huggingface` by `huggingface_hub.snapshot_download(...)` and committed to the volume; the revision's **file manifest** (path, size, digest per file) is recorded and the volume is **re-measured**. The step exists because `@modal.enter()` runs on **every** container start and downloads the model whenever the cache is cold — so without it the GPU class' egress is a **per-container** cost that up to 32 cold containers in R4 would each pay (D29). | the prefetch's own record: the pinned revision, the file manifest, the measured cache size, the download's byte count | **separately authorised** (**A-R2p**), with its own ceiling; its pre-dispatch estimate at or below that ceiling exists and is computed against R1's explicit resource limits and lifecycle bounds (D26) and its autoscaler, volume and egress policies (D27–D29); the download's egress is bounded by `pinned_bytes × (1 + R_download)`; **R2p is a single attempt** — a failed prefetch ends the step, and a retry is a new, separately named and separately approved step (§8.2.5); **R3b and R4 are not dispatchable until R2p has completed and the cache has been verified** against the manifest (§8.1, precondition 11) |
| **R3** | **CPU-only plumbing smoke** on one target (`AC-01` / `AccessControlVault`), run through the producer's own `execute_target()` with the inference stage **not attempted** (D17): the adapter's candidate-generator branch supplies a **checked-in, non-breaching fixture** as the candidate (D19), so the **only** stage whose attempt actually happens is `evm_sandbox`. The `inference`, `refinement`, `evm_sandbox_after_refinement`, `independent_replay` and `trajectory_persistence` stage blocks are still present in the artifact — the producer always writes all six stage keys (`benchmarks/adapters.py:2377-2409`, §5.6 d) — but they record `attempted: false` (§8.2.1). | one throwaway artifact outside `benchmarks/evidence/` | the §8.2.1 gate: the stage matrix is **exactly** §8.2.1 (c); every stage **whose attempt actually happened** satisfies the §5 contract; **nothing is claimed about the stages that were not attempted** — in particular **nothing about the replay**; the caps and the approval **A-R3** of §8.2.5 hold before the first container starts, and the pre-dispatch estimate gate of §8.2.5 is passed — which requires R1's explicit resource limits and lifecycle bounds (D26), its autoscaler, volume and egress policies (D27–D29), because without them the estimate is unbounded and the step is not dispatchable; **R3 is also where the sandbox class' blocking declaration is confirmed empirically** (D29) — the pre-dispatch bound comes from the declaration itself plus the dispatch helper's assertion, and this one CPU container is where the provider's behaviour is observed for the first time, so the question is never first answered on a paid GPU step; **R3 is a single attempt** — exactly one dispatch, no automatic retry (D20); any failure ends the step, and a retry is a new, separately named and separately approved step (§8.2.5) |
| **R3b** | **Inference-plumbing smoke** — one GPU-backed inference call for one target, to obtain a real worker-observed `function_call_id` and the client-resolved `app_id` / `container_id` for that call, **with the closed-loop refinement switched off** (§8.2.2 a). The candidate comes from the model, so the verdict — and with it the replay branch — is **not** predictable in advance (§8.2.2). | one throwaway artifact outside `benchmarks/evidence/` | the §8.2.2 gate; **separately authorised** (**A-R3b**), because it spends GPU time and Modal credits; its caps of §8.2.5 — including its **hard maximum cost** — are fixed **before** the first call, and a pre-dispatch estimate at or below that ceiling exists, computed against R1's explicit resource limits and lifecycle bounds (D26) and its autoscaler, volume and egress policies (D27–D29); while the numeric ceiling of **Q5** is unanswered the step is **not dispatchable**; **R2p has completed and its cache has been verified** against the pinned revision's file manifest, so the GPU container loads the model locally and downloads nothing (§8.1, precondition 11, D29); **R3b is a single attempt** — at most **4** Modal invocations in total (the GPU inference call, the sandbox-CPU verification and at most one sandbox-CPU replay and one persistence-function call; the refinement branch is off, so no `refine_solidity_exploit` call and no second verification), all of them inside that one attempt, and no automatic retry (D20); the cap of 4 is a property of the **R1** producer — against the pre-R1 producer the worst case is 6 (§8.2.5), and this plan does not authorise that; any failure ends the step, and a retry is a new, separately named and separately approved step (§8.2.5) |
| **R4** | Authorised live run: 16 targets, the same provider configuration as the published run (`modal_h100`, `qtum/Qwen3-Coder-30B-A3B-Audit`, `--hypotheses=3` — the flag spelling is settled at `P`, §10.1), **with the closed-loop refinement enabled**, as in the published run (§8.2.5, D23), executed from the detached worktree at `P` (§8.2.6). | a **new** run directory `run_<epoch>_<P[:7]>/` | every stage **whose attempt actually happened** has an observed-or-explicitly-`NOT_AVAILABLE` provenance, and every stage that was not attempted is recorded `attempted: false` and is not claimed; the run completes; the directory suffix equals the manifest's `git.commit_sha[:7]` (§8.2.3); the manifest's SHA is `P` (§8.2.6); the approval **A-R4**, its ceiling **and its wall-clock budget and post-execution deadline** hold — the ceiling itself is unresolved (**Q5**) until the maintainer supplies and approves it, and **R4 declares neither today**, which leaves the storage duration unbounded and the volume term unavailable (D28) — and the estimate is computed against R1's explicit resource limits and lifecycle bounds (D26) and its autoscaler, volume and egress policies (D27–D29), without which it is unbounded and the step is not dispatchable; **R2p has completed and its cache has been verified** against the pinned revision's file manifest (§8.1, precondition 11, D29); the run makes **at most 6 Modal invocations per target and 96 in the run** (≤ 32 GPU + ≤ 48 sandbox-CPU + ≤ 16 persistence-function invocations), the bound of §8.2.5 |
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
| 5 | the refinement loop cannot fire | the closed-loop refinement requires `self.candidate_generator is None` (`:1838`), so R3 cannot make a second, hidden inference call — and R3 needs no refinement switch for that reason: the injected fixture already makes the branch unreachable (§8.2.2 a switches the branch off for R3b, not for R3) | `adapters.py:1833-1840` |
| 6 | **one** Modal call | the candidate is verified by the real CPU worker: `verify_exploit_remote.remote(target_dict, payload_dict)` (`:1826`), a CPU function (`modal_app.py:550-556`, `cpu=config.SANDBOX_CPU_CORES`) | `adapters.py:1826`, `modal_app.py:550-556` |
| 7 | the replay branch is **not** entered | the producer dispatches `verify_replay_remote` only if `verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED` (`:1882-1885`). R3's fixture does not breach the invariant, so the branch is not taken, `replay_attempted` stays `False` (`:1875`) and the replay capture is `attempted=False` (`:2282-2294`) | `adapters.py:1875`, `:1882-1883`, `:2284` |
| 8 | the persistence branch is **not** entered | persistence runs only `if is_verified` (`:2133`), and `is_verified` requires a confirmed replay (`:2104-2109`) — which R3 cannot have | `adapters.py:2104-2109`, `:2133` |
| 9 | the provenance block is the published one | the stage block is written by the same code the 16-target run uses (`:2362-2411`), with **all six** stage keys always present (`:2377-2409`, §5.6 d) | `adapters.py:2362-2411` |

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
| `inference` | `NOT_ATTEMPTED` | **false** | `null` — after R1's fix; today the producer writes the provider's function name here (e, item 7) | nothing. The block is present because the producer always writes all six keys (`adapters.py:2377-2409`); its `attempted: false` is the honest statement |
| `evm_sandbox` | `EXECUTED_WITH_RUNTIME_ENVELOPE` (or `EXECUTED_NO_RUNTIME_ENVELOPE`) | **true** | `verify_exploit_remote` | the real CPU worker call; the worker-observed `function_call_id`; the client-observed `app_id` / `container_id`; the eight remote-EVM facts of §5.4; the stage's own evidence artifact |
| `refinement` | `NOT_ATTEMPTED` | **false** | `null` | nothing — the branch is unreachable for R3 (the injected candidate generator, `:1838`) |
| `evm_sandbox_after_refinement` | `NOT_ATTEMPTED` | **false** | `null` | nothing — there is no second verification without a refinement (`:1860-1867`) |
| `independent_replay` | `NOT_ATTEMPTED` | **false** | `null` | **nothing.** The replay function is not called by R3, so R3 says nothing about `verify_replay_remote` — neither about its `function_call_id` nor about its `container_id` |
| `trajectory_persistence` | `NOT_ATTEMPTED` | **false** | `null` | nothing. Persistence requires a confirmed replay (`:2104-2109`), which cannot exist here |

**The Modal invocations of R3 are exactly one:** `verify_exploit_remote` (**sandbox CPU** —
request 2.0 cores / 2048 MiB; a request is not a cap, §5.6 g). No GPU call, no replay call,
and **no persistence call at all** — the persistence function is not dispatched (§5.6 g). The
pre-dispatch estimate of §8.2.5 is computed over that one invocation.

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

#### (a) The refinement policy of R3b: the branch is switched off — and the switch does not exist yet

R3b is a **plumbing smoke for the inference stage**. It is not a benchmark run, and it is not
a test of the closed-loop refinement. The refinement branch is therefore **disabled for R3b —
and for R3b only**.

* **The switch does not exist at the baseline.** There is no parameter, no flag and no
  configuration field that turns the refinement off today: the loop is entered by the
  conditions of `adapters.py:1833-1840` and by nothing else. The plan does **not** claim that
  R3b's cap of 4 holds today — against the **pre-R1** producer R3b's worst case is **6**
  (§8.2.5). The cap of 4 is a property of the **R1** producer, and R3b is dispatched only
  after R1 and R2 (§8.2), never against a pre-R1 checkout.
* **What R1 adds.** A parameter on the production adapter — `enable_refinement: bool = True` —
  whose **default is today's behaviour**, so the 16-target run (R4) is not changed by it, and
  the runner exposes it for the smoke. The refinement loop's condition gains
  `and self.enable_refinement`. R3b is dispatched with the switch off (D22).
* **Why R3b must not refine.** Two reasons, one about cost and one about honesty. The **cost**:
  the refinement is a **second GPU call** on an H100, and R3b's ceiling (Q5) is fixed before
  its first call — a cap that the step can breach by a branch nobody planned for is not a
  cap. The **honesty**: the refinement fires precisely when the model's candidate *failed*,
  which is the likely outcome of a smoke — so an enabled refinement would make R3b's stage
  matrix outcome-dependent in a second, unplanned way, on top of the replay branch that is
  already outcome-dependent (§8.2.2 (b)).
* **What R3b therefore does not prove.** Nothing about the refinement branch: neither its
  `function_call_id`, nor its `container_id`, nor its stage block, nor its place in the
  function list. That path is covered at **no cost** by the mocked producer test (**T16**),
  and for real by R4 itself (§8.2.5) — whose worst case is stated there.
* **The negative test.** **T13** pins the switch: in the R3b configuration the producer must
  not dispatch `refine_solidity_exploit` at all, and the artifact's `modal_functions` must
  not name it. A future edit that re-enables the branch in R3b fails the suite instead of
  silently raising the step's cost.

| Aspect | R3 (CPU) | R3b (GPU) |
|---|---|---|
| Stages exercised | `evm_sandbox` **only** | `inference` and `evm_sandbox`; `independent_replay` **only if** the model's verdict triggers it (`adapters.py:1882`), and `trajectory_persistence` only if that replay confirmed the breach (`:2104-2109`). The `refinement` and `evm_sandbox_after_refinement` stages are **never** attempted — the branch is switched off (§8.2.2 a) |
| Modal invocations | exactly **1** (`verify_exploit_remote`, **sandbox CPU** — request 2.0 cores / 2048 MiB, §5.6 g) | **1** GPU inference call + **1** **sandbox-CPU** verify + **≤ 1** **sandbox-CPU** replay + **≤ 1** **persistence-function** call — worst case **4**, all of them inside the step's **single** attempt (§8.2.5, D20). The refinement branch is switched off, so there is no `refine_solidity_exploit` call and no second verification; against the **pre-R1** producer the worst case would be **6** (§8.2.5). The persistence call is a container of its own, priced at the **published Function CPU and memory rates** — not at the sandbox-CPU rate, not at zero and not at a rate class of its own (§5.6 g, D25) |
| Cost | sandbox-CPU containers only — its own, smaller ceiling | one GPU inference call — Modal credits — its own **hard maximum cost** (§8.2.5); the optional replay and persistence calls are priced separately (§8.2.5) |
| Authorisation | its own approval **A-R3** (§8.2.5) | **separate, explicit authorisation** **A-R3b** |
| Proves | the producer/validator plumbing, the envelopes, the evidence references, the EVM fact sourcing | that the inference `function_call_id` is worker-observed, and that the client resolves the provider-issued `app_id` / `container_id` for that call — and, **only if** the replay was actually dispatched, that the replay stage's identities resolve as well |
| Does **not** prove | anything about inference; **anything about the replay** | the 16-target behaviour |

#### (b) R3b's stage matrix is outcome-dependent, and that is recorded, not assumed

Its candidate comes from the model, so whether the replay branch is entered is decided by the
verdict and not by the plan:

| Stage | Expected in R3b | Condition |
|---|---|---|
| `inference` | `attempted: true` | always — the GPU call is the point of R3b |
| `evm_sandbox` | `attempted: true` | always — the candidate is verified |
| `refinement` | `attempted:` **always `false`** | never — the branch is switched off for R3b (§8.2.2 a). The block is present because the producer writes all six stage keys (§5.6 d) |
| `evm_sandbox_after_refinement` | `attempted:` **always `false`** | never — there is no second verification without a refinement (`:1860-1867`) |
| `independent_replay` | `attempted:` **either** `true` or `false` | `true` only if the model's candidate breaches the invariant (`adapters.py:1882`); `false` otherwise. R3b **records** which of the two happened and claims the replay **only** when it is `true` |
| `trajectory_persistence` | `attempted:` **either** `true` or `false` | `true` only if the replay confirmed the breach (`is_verified`, `adapters.py:2104-2109`) |

A smoke report that says "the replay stage was exercised" is therefore only true if the
artifact records `independent_replay.attempted = true`. A report that says it was **not**
exercised is true in every other case, and is not a defect of the smoke.

**R3b is a single attempt.** Like R3 (D20), R3b is dispatched once and is never retried
automatically. Its worst case of 4 Modal invocations is the **content of that one attempt** —
the GPU call plus the CPU stages the model's verdict may trigger, with the refinement branch
switched off (§8.2.2 a) — not a budget that may be spent twice. If the attempt fails, R3b
ends there: the failure is recorded, the app is stopped, and the sequence does not continue
into R4 (§8.3). A retry is **not** a second attempt of R3b: it is a **new, separately named
step** (for example `R3br`) with its own approval (**A-R3br**), its own hard maximum cost and
its own pre-dispatch estimate.

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
a paid call whose cost nobody has bounded. The same holds for the **bounds** the estimate
multiplies: until R1 declares the explicit request/limit pairs and the explicit lifecycle
bounds, the estimate is unbounded and the step is not dispatchable either (D26) — and the
same holds for the container count, the volume quantity and the egress quantity, which R1
must bound as well (D27–D29).

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

Four steps of §8.2 start Modal containers, and **all four cost money**. A CPU container on
Modal is compute, not a free local test: it is billed per second, and the GPU step is
billed per second of an H100. Every one of the four steps therefore gets its own hard cap,
its own stop condition and its own explicit approval — fixed **before** the step runs — and
its own **pre-dispatch cost estimate** that must be at or below its ceiling before the first
container is dispatched. The fourth is **R2p**, the model-cache prefetch: one CPU container,
one attempt, its own approval **A-R2p** (D29).

#### The per-target Modal invocation trace

Every invocation count below is derived from **one** table — the trace of a single target
through the producer (`benchmarks/adapters.py:1785-1871`, `:1882-1885`, `:2133-2145`;
§5.6 (a)):

| # | Call | Function | Resource class | Dispatched when |
|---|---|---|---|---|
| 1 | the inference | `ProductionAuditAgent.generate_solidity_exploit` | **GPU** (H100) | always |
| 2 | the first verification | `verify_exploit_remote` | **sandbox CPU** — request 2.0 cores / 2048 MiB; a request is not a cap (§5.6 g) | always |
| 3 | the refinement | `ProductionAuditAgent.refine_solidity_exploit` | **GPU** (H100) | the first verdict is neither `INVARIANT_BREACH_UNREPLAYED` nor `EXPLOIT_CONFIRMED` |
| 4 | the second verification | `verify_exploit_remote` | **sandbox CPU** — request 2.0 cores / 2048 MiB (§5.6 g) | the refinement returned a usable payload |
| 5 | the replay | `verify_replay_remote` | **sandbox CPU** — request 2.0 cores / 2048 MiB (§5.6 g) | the final verdict is `INVARIANT_BREACH_UNREPLAYED` |
| 6 | the persistence | `record_trajectory_remote` | **persistence function** — own profile: no `cpu=`/`memory=` declared (request 0.125 cores / 128 MiB, default CPU limit 16.125 cores, no hard memory limit), `timeout=60`, persistent volume attached; billed over the container's lifetime — startup + execution + idle (§5.6 g) | the replay confirmed the breach |

**Per target: at most 6 calls — 2 GPU + 3 sandbox-CPU + 1 persistence function.** There is no
seventh call: `max_refinements = 1` (`:1831`), so the refinement is attempted at most once,
and the replay and the persistence each depend on the verdict of the call before them.

**What the published run actually made** — measured, not assumed (§5.6 (b)): every one of the
16 targets made **4** calls — the 14 refined ones `generate → verify → refine → verify`, the
two confirmed ones `generate → verify → replay → persist` — so **64** calls in the run, split
by resource class into **30 GPU + 32 sandbox-CPU + 2 persistence-function** invocations
(14 × (2 GPU + 2 sandbox-CPU) + 2 × (1 GPU + 2 sandbox-CPU + 1 persistence)).

**The step totals:**

| Step | Targets | Invocations | GPU | sandbox CPU | persistence function |
|---|---|---|---|---|---|
| **R3** | 1 — no inference, no refinement | **1** | 0 | 1 | 0 |
| **R3b**, refinement switched off (§8.2.2 a) | 1 | **≤ 4** | 1 | ≤ 2 | ≤ 1 |
| **R3b** against the pre-R1 producer — **not authorised** | 1 | ≤ 6 | 2 | ≤ 3 | ≤ 1 |
| **R4** | 16 | **≤ 96** | ≤ 32 | ≤ 48 | ≤ 16 |
| **R4**, the published run's measured trace | 16 | 64 | 30 | 32 | 2 |

The three total caps — **R3 = 1**, **R3b ≤ 4**, **R4 ≤ 96** — are unchanged by this
refinement; only the **split by resource class** is corrected.

The estimate gate below multiplies **one rate per resource class** by the invocation count of
**that** class — the numbers of this table — so the estimate refers to counts this plan
defines, not to a number nobody has written down.

#### The caps

| Step | Compute | Hard cap | Timeout / stop condition |
|---|---|---|---|
| **R2p** (model-cache prefetch) | **exactly 1** CPU container — no GPU — that downloads the **pinned revision** of the model into the volume's cache and commits it (§8.2, D29); the file manifest and the re-measured volume are its output | **1** container, **exactly 1 attempt** — no automatic retry (D20) — a wall-clock budget of its own, a **post-execution deadline** of its own (D28), and a **monetary ceiling of its own** (Q5) | the client aborts the attempt at its wall-clock budget, stops the app and records the failure; **any failure ends the step** — there is no second attempt, and a retry is a new, separately named and separately approved step (D20). The **R1 resource precondition** below must hold first, and the download's egress must be bounded by `pinned_bytes × (1 + R_download)`; without them the estimate has **no upper bound** and the step is **not dispatchable** (D26–D29) |
| **R3** (CPU plumbing smoke) | **exactly 1** Modal invocation — the **sandbox-CPU** `verify_exploit_remote`; 1 CPU container, 1 target (`AC-01`), **0** inference calls, **0** replay calls, **0** persistence calls (§8.2.1 a, c) | **1** container, **1** target, `--hypotheses=1`, **exactly 1 attempt** — no automatic retry (D20) — a wall-clock budget of **20 minutes** for that attempt, a **post-execution deadline** of its own (D28), and a **monetary ceiling of its own** (Q5) | the per-call timeout stays at the published value (`timeout_sec = 120`, §10.1); the client aborts the attempt at the 20-minute budget, stops the app (`modal app stop`) and records the failure; **any failure ends the step** — there is no second attempt, and a retry is a new, separately named and separately approved step (D20). The **R1 resource precondition** below must hold first: without explicit request/limit pairs, explicit lifecycle bounds, a provider-enforced container count, a bounded volume over a bounded duration and a bounded egress the estimate has **no upper bound** and the step is **not dispatchable** (D26–D29) |
| **R3b** (inference-plumbing smoke) | **worst case 4** Modal invocations — **1** GPU inference call + **1** **sandbox-CPU** `verify_exploit_remote` + **≤ 1** **sandbox-CPU** `verify_replay_remote` + **≤ 1** **persistence-function** `record_trajectory_remote` (§8.2.2, §8.2.5); 1 GPU container (`modal_h100`), 1 target, **exactly 1** inference call — all of them inside the step's **single** attempt. The **refinement branch is switched off** for this step (§8.2.2 a): no `refine_solidity_exploit` call and no second verification. Against the **pre-R1** producer the worst case would be **6** — which is why R3b is dispatched only after R1 and R2, and why the plan authorises no pre-R1 R3b | **1** GPU call, `--hypotheses=1`, **exactly 1 attempt** — no automatic retry (D20) — whose worst case is the 4 invocations above, a wall-clock budget of **20 minutes**, a **post-execution deadline** of its own (D28), and a **hard maximum cost** of its own (Q5) | the same abort rule; **any failure ends the step** — a failed R3b **ends the sequence**, R4 does not start (§8.3); there is no second attempt, and a retry is a new, separately named and separately approved step (D20). The **R1 resource precondition** below must hold first: without explicit request/limit pairs, explicit lifecycle bounds, a provider-enforced container count, a bounded volume over a bounded duration and a bounded egress the estimate has **no upper bound** and the step is **not dispatchable** (D26–D29) |
| **R4** (the 16-target run) | 16 targets × H100, the published configuration — **one** authorised run: the 16 targets are dispatched once, and a target that fails inside the run is that target's recorded result, not a retried attempt (D20). The **refinement branch is enabled**, because it is part of the published configuration — 14 of the 16 published targets refined (§5.6 b) — so the worst case is **6** invocations per target: **≤ 96** for the run, split as **≤ 32** GPU + **≤ 48** sandbox-CPU + **≤ 16** persistence-function (the trace table above). The published run's own measured trace was **64** (**30** GPU, **32** sandbox-CPU, **2** persistence-function) | the monetary ceiling of **Q5** (§10.3) — no per-call cost may exceed it — **a wall-clock budget of its own** and **a post-execution deadline of its own**, neither of which the plan sets today and both of which the maintainer must supply with the ceiling (**Q5**): without them the storage duration is unbounded and the volume term is unavailable (D28) — and **exactly 1** run attempt (D20) | the per-call timeout stays at `timeout_sec = 120` per target; the operator stops the app when the accumulated spend reaches the ceiling **or** when the declared wall-clock budget expires, whichever comes first; the partial result and its billing window are published, and the run is **not** retried silently. The **R1 resource precondition** below must hold first: without explicit request/limit pairs, explicit lifecycle bounds, a provider-enforced container count, a bounded volume over a bounded duration and a bounded egress the estimate has **no upper bound** and the step is **not dispatchable** (D26–D29) |

#### The R1 resource precondition: explicit limits, an enforced container count and a bounded lifecycle

A pre-dispatch estimate needs an **upper bound**, and an upper bound needs three things the
declarations of today do not provide: a **limit the provider enforces** (a request is not a
limit, §5.6 g), a **bounded billable lifetime of the container** (an execution timeout is not
the billable lifetime, §5.6 g) and an **autoscaler that cannot add billable containers of
its own** (the invocation bound is only provider-enforced when no container is kept warm or
buffered without an invocation, §5.6 g). R1 therefore has to change the three container
classes before any of the compute steps may be dispatched:

| Container class | What R1 must declare | What it buys the estimate |
|---|---|---|
| **sandbox CPU** — `verify_exploit_remote`, `verify_replay_remote` | `cpu=(request, limit)` with `request = config.SANDBOX_CPU_CORES` and an explicit `limit`; `memory=(request, limit)` with `request = config.SANDBOX_MEMORY_MB` and an explicit hard `limit`; an explicit `startup_timeout`; an explicit `scaledown_window`; **and** the autoscaler declarations of the next subsection (`min_containers=0`, `buffer_containers=0`, `max_containers=<cap>`) | a provider-enforced ceiling on CPU (host throttling) **and** on memory (OOM kill), plus a bounded `T_billable`, plus a container count that cannot exceed the invocation count for any reason but the invocations themselves |
| **GPU container** — `ProductionAuditAgent` | `cpu=(request, limit)`, `memory=(request, limit)`, `startup_timeout`, `scaledown_window`, **and** the autoscaler declarations of the next subsection — the class declares `gpu=…` and **no** CPU and **no** memory today (`modal_app.py:74-80`), so both of its non-GPU lines are currently unbounded | the same, for the CPU and memory lines of the H100 container, and for its container count |
| **persistence function** — `record_trajectory_remote` | `cpu=(request, limit)`, `memory=(request, limit)`, `startup_timeout`, `scaledown_window`, **and** the autoscaler declarations of the next subsection — it declares **no** `cpu=` and **no** `memory=` today (`modal_app.py:695-700`), so it runs on the 0.125-core / 128 MiB default request with no memory ceiling | the same, for the persistence container, and for its container count |

Four properties of the limits and the lifecycle are **testable**, and they belong to R1's
acceptance (AC 27):

1. the declared **limit** is **greater than or equal to** the declared **request** in both
   dimensions — otherwise the bill's floor (the request) would exceed the bound the estimate
   uses;
2. the **CPU limit is explicit**, so it does not depend on the default `request + 16` rule,
   which moves whenever the request moves;
3. the **memory limit is explicit and hard** — `memory=(request, limit)`, never a scalar — and
   it is high enough for the real workload: a `forge` compile of the published targets is not
   bounded by 2048 MiB, so the limit must not OOM-kill the run. The value is fixed in R1 and
   recorded in the approval record;
4. `startup_timeout` and `scaledown_window` are **explicit**, so that
   `T_billable = startup_timeout + timeout + scaledown_window` is a **number** and not a
   default that can change under the estimate.

#### The autoscaler policy: an enforced container-count bound (D27)

The invocation count is only a container bound if **every billed container serves at least one
invocation**. The provider is free to break that: `min_containers` keeps containers warm "even
when the Function is inactive", `buffer_containers` maintains an idle buffer "while the
Function is active" (Modal Docs, *Scaling out*). Both are billed during the step while
carrying no invocation at all, and the repository declares **neither** — nor
`max_containers`, which is the only provider-enforced ceiling on a class's concurrency. The
provider's documentation states **no default** for `min_containers` / `buffer_containers`, so
an unset autoscaler setting is an unknown in the same sense an unset memory limit is
(§5.6 g).

R1 therefore declares, for **each** of the three container classes:

| Declaration | Value | What it enforces |
|---|---|---|
| `min_containers` | **0** | no container is kept warm while the Function is inactive ⇒ every billed container exists to serve a demand |
| `buffer_containers` | **0** | no idle container is maintained while the Function is active ⇒ no billed container is idle by design |
| `max_containers` | the class's **union ceiling** — the largest cap any authorised step uses for that class (table below) | the **concurrency** of the class — a second, independent provider-enforced bound |
| `scaledown_window` | explicit (R1, D26) | the idle tail of `T_billable` is a number |

**The deployed configuration — one union ceiling, never changed between the steps.** A
`max_containers` is a property of the **deployment**, not of a step, so the deployed value is
the **union** of the caps of every authorised step, and the *effective* cap of a smaller step
is enforced at dispatch time by a mechanism that cannot raise it:

| Container class | `min_containers` | `buffer_containers` | `max_containers` (deployed, R1) | per-step invocation caps |
|---|---|---|---|---|
| **sandbox CPU** | **0** | **0** | **48** | R3 = 1, R3b ≤ 2, R4 ≤ 48 |
| **GPU class** | **0** | **0** | **32** | R3b = 1, R4 ≤ 32 |
| **persistence function** | **0** | **0** | **16** | R3b ≤ 1, R4 ≤ 16 |

The deployed ceiling is **never lowered and never raised** during the sequence. R3 → R3b → R4
is possible **in that order** precisely because the deployed value is the union (48 / 32 / 16)
and **not** the first step's value. An earlier draft of this plan deployed R3's own sandbox
value of 1 and then tried to raise it to 2 for R3b and to 48 for R4 under a "tightening-only"
rule — that lifecycle was **internally impossible**: a cap that may only be tightened cannot
go from 1 back to 2, let alone from 1 to 48. The lifecycle above replaces it with one that is
executable in the stated order and still fail-closed: the deployed ceiling is the **union**,
the per-step cap is enforced by the dispatch helper, and neither can be raised.

**How the GPU and the persistence pools come into use — without a separate "enabling" step.**
They are **deployed from the start** at their union ceilings (32 and 16) and are never
touched afterwards, so there is nothing to enable and nothing to tighten: in **R3** they are
simply **not dispatched**, and the dispatch helper's invocation budget for them in R3 is
**0**, so a stray GPU or persistence call in R3 is refused by the helper and recorded. In
**R3b** and **R4** their per-step caps (1 and 1, then 32 and 16) are ≤ their deployed
ceilings, so the ceiling assertion passes and the concurrency gate bounds them. A class that
a step does not use therefore costs **nothing** in that step — no container starts, because a
container only exists to serve a dispatch (D27).

One provider detail matters for the GPU class: a `modal.Cls` autoscales **per
instance-parameter combination** ("instances with different parameter values use separate
container pools which autoscale independently", Modal Docs, *Scaling out*) —
`ProductionAuditAgent` declares **no** `modal.parameter` (`modal_app.py:74-80`; the only
parameterised class in the file is `DevReasoningAgent`, `modal_app.py:241-242`, which is not
part of this trace), so it has exactly **one** container pool and one `max_containers`.

**The repository makes no autoscaler call at all.** The provider allows the settings to be
changed at runtime without a redeploy — "It's also possible to view and update the autoscaler
settings dynamically (i.e., without redeploying the App) using the `Function.autoscaler.update()`
method" — and "the autoscaler settings will revert to the configuration in the function
decorator the next time you deploy the App" (Modal Docs, *Scaling out*). A runtime override is
therefore a **stale, invisible** object: it can raise a cap without a line of the repository
changing, and it survives until the next deploy resets it.

So the repository contains **no mutating autoscaler call anywhere**. R1 adds **no**
`update_autoscaler(min_containers=…, max_containers=…, …)` call, and R2 adds a test that
fails if any mutating call site appears. With no mutating call:

1. **no cap can be raised at runtime** — the deployed decorator values are the only values that
   ever exist, so "tightening-only" stops being a rule that has to be policed and becomes a
   **property** of the design;
2. **no stale or dynamic override can survive** a step, a redeploy or a rollback — a redeploy
   restores the decorator's values by the provider's own rule, and there is nothing else to
   restore;
3. the per-step cap is therefore enforced **client-side**, by the dispatch helper R1 adds, and
   the deployed ceiling is the provider's outer backstop (below).

**The per-step effective cap: the dispatch helper.** R1 adds one dispatch helper — the only
path through which this workflow dispatches a Modal call — and it enforces three things per
step:

1. an **invocation budget** per container class: at most `invocations(c)` dispatches of class
   `c` in the step; the helper **refuses** the next one and records the refusal. The budget is
   the trace table's number (§8.2.5), so the helper is what turns the trace into an executed
   contract;
2. a **concurrency gate** per container class: at most `cap(c)` dispatches of class `c` in
   flight at the same time — a client-side semaphore in the dispatch path. The cap comes from
   the step's **approval record**, which is fixed before the step;
3. a **ceiling assertion**: `cap(c) ≤ max_containers_deployed(c)`. If a step's approved cap
   exceeds the deployed ceiling, the helper refuses to dispatch and the step is recorded as
   **"not dispatched — deployed ceiling too low"**.

The cap table is part of the **approval record**, not a runtime parameter: raising a per-step
cap is a change to the approval record and needs a **new approval**, exactly like raising the
monetary ceiling. There is no code path that can raise it, and no code path that can raise the
deployed ceiling either.

**The read-back.** The effective settings are read back **before the first container** of
each step and **again after the step**, and both readings are recorded in the approval record.
The pinned local SDK (1.5.5) has **no** `Function.autoscaler` namespace, so the read-back is
the **no-argument** call `Function.update_autoscaler()`: its own documentation states that
"Unspecified parameters will retain their current value, i.e. either the static value from the
function decorator, or an override value from a previous call to this method" — a call with
**no** argument therefore changes nothing and returns the current settings as a
`modal.types.FunctionAutoscalerSettings`. R1 contains exactly **one** such call site (in the
dispatch helper, before the first container) and **no** mutating one. If the pinned SDK
provides **no** read-back at all, the step is **not dispatchable**: an unverifiable cap is an
unbounded one.

**What this buys the estimate — and which of the bounds the provider enforces.** The
distinction is stated explicitly, because the estimate depends on it and the reader must not
have to guess which of the four bounds is the provider's:

| Bound | Enforced by | What it bounds |
|---|---|---|
| `min_containers=0`, `buffer_containers=0` | **the provider** | every billed container exists to serve a demand ⇒ `containers(c) ≤ invocations(c)` |
| `max_containers` (deployed: 48 / 32 / 16) | **the provider** | the **concurrency** of a class — the outer backstop |
| invocation budget per class per step | the dispatch helper (client) | the number of dispatches of class `c` in the step |
| concurrency gate per class per step | the dispatch helper (client) | the dispatches of class `c` in flight |

The **compute** terms of the estimate multiply `containers(c)`, and that bound is the
**provider-enforced** one:

```
containers(c)             ≤ invocations(c)               # provider-enforced: min_containers=0, buffer_containers=0
concurrent_containers(c)  ≤ max_containers_deployed(c)   # provider-enforced: the deployment's concurrency cap
concurrent_containers(c)  ≤ cap(c)                       # client-enforced: the step's own concurrency gate
```

The first line is what the estimate multiplies (§8.2.5). The concurrency bounds are the
wall-clock consequence: at most `cap(c)` containers of a class are billed at the same moment,
which is what makes the step's wall-clock budget meaningful. Note that `max_containers` does
**not** cap the number of containers a class starts *over time* — a container that scales down
and is replaced by a new one is a second container — which is exactly why the estimate's bound
is the invocation count and not `min(invocations, max_containers)`. **A concurrency cap is
not a cumulative container-creation cap**: `max_containers_deployed(c)` appears in a
concurrency bound and in the dispatch helper's ceiling assertion, and nowhere else. It is
never multiplied into a cumulative quantity — the container count of the compute terms, the
payload egress or the protocol allowance — and no cumulative quantity is ever clamped by it,
because such a clamp would sit **below** the worst case the step can actually reach (D29).

**Why the client-side gate does not weaken the cost bound.** If the helper were bypassed by a
bug, the per-step caps would degrade to the deployed ceiling — 48 concurrent sandbox
containers instead of 1. That would break the *wall-clock* budget, not the *cost* bound: the
number of billed containers stays bounded by the invocation count (a provider-enforced fact,
because `min_containers=0` and `buffer_containers=0`), and the invocation budget is itself the
number of dispatches the step is allowed to make at all. The compute term therefore survives
the failure of the client-side gate; the step's own wall-clock budget and its stop condition
are what end a degenerate step (§8.2.5, D28).

#### The volume bound: baseline, increment, retention and the fail-closed stop (D28)

The persistent volume is a **billable object of its own**: the provider prices it per GiB-month,
separately from the compute of the container that writes to it (§5.6 g). The repository's
volume is `aegis-model-cache` (`core/config.py:9`), mounted at `/vol/models`
(`modal_app.py:53`), and three different things live in it:

| What | Where | How big |
|---|---|---|
| the model cache | `/vol/models/huggingface` (`core/config.py:10`), written by the **prefetch step R2p** (D29) — the GPU class' inference path no longer downloads anything, it only reads the cache (`modal_app.py:87-113` becomes `local_files_only=True` plus a manifest check) | the **dominant** term — the pinned model's byte size, **once**, in R2p; 0 in R3b/R4 |
| the training trajectories | `/vol/models/trajectories` (`core/config.py:11`), one JSON file per confirmed target, written and committed by the persistence function (`modal_app.py:702-711`) | **one file per dispatched persistence call** — 0 for R3, ≤ 1 for R3b, ≤ 16 for R4 |
| everything else already on the volume | — | **measured**, not assumed |

The estimate's volume term is bounded in three pieces — **how many bytes**, **for how long**,
and **what happens to them afterwards**:

```
volume_GiB(step)       = baseline_GiB + incremental_GiB(step)
T_store(step)          = T_exec(step) + T_post_exec_to_publication(step) + T_retention(step)
months(step)           = 1 + ceil(T_store(step) / 28 days)     # conservative calendar treatment
volume_GB_months(step) = volume_GiB(step) × months(step)
```

`T_store` has **three** terms, not two. The compute step does not end where the storage
ends, and it does not end where the publication happens either: the bytes written during the
execution stay stored while the step is **post-processed** — validated, reported, committed,
reviewed, published — and the 30-day retention clock starts only **after** the publication.
The interval between the end of the execution and the publication is therefore part of the
storage duration, and it is bounded by its own declaration, `T_post_exec_to_publication`.

1. **`baseline_GiB` is measured, immediately before the dispatch.** The measurement is the
   recursive listing of the volume — `modal volume ls aegis-model-cache --json` on the CLI, or
   `modal.Volume.listdir(path, recursive=True)` in the SDK, whose entries carry their size —
   summed over the entries. It is recorded in the approval record with its date. **If the
   listing fails, the step is not dispatched**: an unmeasurable volume is not a small volume,
   it is an unknown one, and the rule of §8.2.5 is the same in both directions.
2. **`incremental_GiB` is bounded by construction, not by hope.** The trajectory write is
   capped **in the producer**: R1 fixes a hard byte cap for one trajectory payload, and the
   persistence function refuses a larger payload instead of writing it (the refusal is an
   infrastructure error, recorded as such). The model-cache write belongs to **R2p**, and its
   size is the **pinned model revision's** byte size — read from the provider's own file
   listing and recorded with its date; a revision that cannot be pinned to a byte size has **no
   bound**, and R2p is then not dispatchable. After R2p has committed, the cache is part of the
   **measured baseline** of the later steps — it is never counted twice.
3. **`T_store` — the storage duration — is bounded, and it is a sum, not a maximum.** The
   bytes exist **from the first write** (during the execution) **until the deletion is
   verified** (up to 30 days after the publication). The earlier draft of this plan priced
   `(baseline + increment) × 1 month`, which is an upper bound only if the whole
   first-write-to-deletion interval fits inside one month. It does not: the execution happens
   **before** the publication, and the 30-day retention starts **after** it. The interval is
   therefore the **sum**:
   * `T_exec(step)` — the step's **hard wall-clock budget**, a number in the approval record.
     It is bounded twice over: by the declared budget itself, and by the monetary ceiling,
     because the estimate's own worst-case burn rate turns a finite ceiling into a finite
     duration: `T_exec(step) ≤ ceiling(step) / burn_rate_upper_bound(step)`. R3 and R3b
     declare a 20-minute budget; **R4 declares none today** — its stop condition is the
     monetary ceiling — so **R4's volume term is unavailable** until the maintainer declares
     R4's wall-clock budget together with its ceiling (**Q5**). An unbounded storage duration
     is an unbounded storage quantity, so **R4 is not dispatchable** on that ground alone.
   * `T_post_exec_to_publication(step)` — the step's **declared post-execution deadline**:
     the bounded interval between the end of the compute step and the publication of its
     artifacts. It covers everything that happens to the run's bytes **after** the last
     container has finished and **before** the 30-day retention clock starts — the
     post-execution validation of the artifacts (§8.2.1, §10.2), the generation of the
     replacement report, the commit, the review of the Draft PR, and any queue or wait time
     in between. The bytes written during the execution remain stored throughout that
     interval, so the interval belongs to `T_store`; the two-term interval of the earlier
     draft (`T_exec + T_retention`) silently priced this period as **zero**. The interval is
     bounded by an **explicit wall-clock deadline** in the step's approval record and by the
     **stop-and-cleanup rule** below: if the deadline expires before the publication, the
     cleanup rule of this subsection runs — the run's bytes are deleted and the deletion is
     verified — and the step is recorded as a **failed** step with that cleanup event, not as
     a published one. If the deadline cannot be bounded at all, `T_post_exec_to_publication`
     is unknown, `T_store` is unknown, the **volume term is unavailable** and the step is
     **not dispatchable** — the same fail-closed rule as the unbounded `T_exec`. **No step
     declares such a deadline today**, so on the strength of this term alone the volume term
     of R2p, R3, R3b and R4 is unavailable. The cleanup can only ever **shorten** the
     interval: the estimate prices the full `T_store` and never assumes an early deletion.
   * `T_retention` — **30 days**, from the publication to the verified deletion. The abort
     path deletes immediately, but the bound keeps the **same 30 days**: the abort cleanup can
     itself fail, and the plan does not assume a deletion it has not verified.
4. **`months(step)` — the calendar treatment.** The provider bills a volume per GiB-month.
   The plan prices **whole months, rounded up**, and counts a span of `T` days as touching at
   most `1 + ceil(T / 28)` calendar months — 28 days is the shortest month, so no span of `T`
   days can cross more month boundaries than that. Rounding up is conservative against a
   prorated billing convention, and the extra month covers a span that crosses a boundary.
   **Rechecked against the revised total interval**: the formula is unchanged in form, but
   the `T` it is applied to is now the **whole** `T_store` — the execution **plus** the
   post-execution interval **plus** the retention — and not the two-term sum of the earlier
   draft. The recheck holds: a span of `T` days touches at most `1 + ceil(T / 28)` calendar
   months, because the shortest month is 28 days — starting on the last day of a 28-day
   month, a span of `T` days covers the remainder of that month, at most `floor(T / 28)`
   further whole months and a partial one, so it can touch one more month than the whole
   months it contains. **Worked examples** (illustrative numbers, not a budget):

   | Case | `T_exec` | `T_post_exec_to_publication` | `T_retention` | `T_store` | `months = 1 + ceil(T_store / 28 d)` | the volume term |
   |---|---|---|---|---|---|---|
   | the short case | 6 h | 4 h | 30 d | 30 d + 10 h = **30.417 d** | `1 + ceil(1.0863) = 1 + 2 =` **3** | `(baseline + increment) × 3` GiB-months |
   | the boundary case | 26 d | 2 d | 30 d | **58 d** | `1 + ceil(2.0714) = 1 + 3 =` **4** | `(baseline + increment) × 4` GiB-months |

   The second case is the one the omitted interval would have hidden: without
   `T_post_exec_to_publication` the total would be 56 days — exactly on the 28-day boundary —
   and the formula would have returned `1 + ceil(56 / 28) = 3` months, **one whole month
   below** the truth. Note that the 30-day retention alone already spans three calendar
   months (`1 + ceil(30 / 28) = 3`), so the two-term interval was never the same quantity as
   the three-term one — the interval is priced as a **sum**, not as a maximum (D28).

**The estimate therefore covers the complete quantity — the execution, the post-execution
interval *and* the post-run retention**: `(baseline_GiB + incremental_GiB) × (1 + ceil(T_store /
28 days))` for the worst case, with `T_store = T_exec + T_post_exec_to_publication +
T_retention`. Two clarifications the earlier draft left open:

* the **baseline** is priced for the **same bounded interval** — conservatively, because a
  GB-month is a GB-month whatever the reason. The baseline's storage **after** the run's
  window is a **standing workspace cost** and is excluded from the run's estimate by the same
  rule that excludes the workspace's pre-existing compute from it; the estimate covers the
  run's attributable window;
* **all run-created bytes are counted until the deletion is verified.** The increment is
  priced for the whole `T_store` window — the estimate never assumes an early deletion — and
  if the deletion cannot be verified, the increment stays in the **baseline of the next
  step**, where it is measured and priced again. The next step's baseline measurement is
  therefore not a formality: it is the mechanism that keeps a failed cleanup from being
  forgotten.

The provider's published free allowance (1 TiB/month, §5.6 g) is recorded as a **fact** in the
approval record and is deliberately **not** netted out of the estimate: the allowance belongs
to the workspace's plan, not to the run, and an estimate that depends on a plan-level
allowance is not a worst case.

**The fail-closed stop.** Five conditions end the step rather than continue it:

* the persistence function's own byte cap is exceeded — the write is refused, the step fails,
  and the failure is recorded (the cap is enforced in the producer, so the container is never
  billed for the oversized write);
* the volume's measured size after the step exceeds `baseline_GiB + incremental_GiB` — the app
  is stopped (`modal app stop`), the step is recorded as an **overrun**, and the cleanup rule
  runs;
* the volume cannot be measured after the step — the step is recorded as **not measurable**,
  the cleanup rule runs, and the residual is reported as an open item rather than as a
  passing bound;
* the step's **storage duration** cannot be bounded — no declared wall-clock budget and no
  finite ceiling, so `T_store` is unknown — the volume term is **unavailable** and the step is
  **not dispatchable** (this is R4's state today, §8.2.5, D28);
* the step's **post-execution interval** cannot be bounded — no declared post-execution
  deadline before the publication (D28) — so `T_store` is unknown even though `T_exec` is
  known — the volume term is **unavailable** and the step is **not dispatchable**. This is the
  state of **R2p, R3, R3b and R4 today**, because no step declares that deadline yet.

**A commit is not a fee.** The provider publishes **no** separate commit charge — the volume's
price is its storage rate per GiB-month (§5.6 g) — so the "write/commit" of the persistence
function contributes to the **bytes stored**, not to a second line of the estimate. The
estimate does not invent a commit fee, and it does not price the commit twice.

#### The network-egress bound (D29)

The provider publishes a **separate rate class** for network egress, distinct from compute
and from storage (§5.6 g). It is not a theoretical line for this workflow: the repository's
own published raw billing export carries a **non-zero** `Network Egress` line item for the
canonical app session `ap-EDUitOwWeMrIdYbTh4kB63` (`aegis-rlvr-security`, 2026-11-09) —
`$2.6E-7` — alongside its `H100`, `CPU` and `Memory` lines
(`benchmarks/evidence/modal_billing_report_raw.json`). An estimate that omits egress is
therefore an estimate of a cost that has already been observed.

**The quantity is per container, and the step total is a sum over the step's containers.** The
earlier draft of this plan wrote `network_egress_GiB(step) = Σ_c egress_bound_GiB(c)` without
saying whether a class's bound was **per container** or **for the whole step** — and its GPU
row was **wrong**: it priced **one** pinned model revision, while the same plan allows up to
**1** GPU container in R3b and **32** in R4. The reason is in the source: the GPU class'
`@modal.enter()` (`modal_app.py:87-113`) runs
`AutoModelForCausalLM.from_pretrained(..., cache_dir=…)`, and `@modal.enter()` runs on
**every container start**, not once per app. A cold or incomplete cache therefore makes
**each** cold GPU container download the model. A shared volume does **not** prevent that:
the commit happens **after** the load (`modal_app.py:109-113`), so concurrent cold starts
race on an empty cache. Without a prefetch the honest bound is
`cold_gpu_containers × pinned_bytes` — **not** `pinned_bytes`.

**The model download is therefore moved out of the run steps, into a separately approved
prefetch step.** R1 adds **R2p — the model-cache prefetch** (§8.2):

* **one CPU container**, one attempt, no GPU: the pinned **revision** (a commit SHA, not a
  branch name) of `qtum/Qwen3-Coder-30B-A3B-Audit` is downloaded into the volume's cache by
  `huggingface_hub.snapshot_download(repo_id=…, revision=…, cache_dir=config.MODEL_CACHE_DIR)`
  — the same cache layout `from_pretrained` reads — followed by `model_volume.commit()`;
* the **file manifest** of that revision (path, size and digest per file) is recorded, and the
  volume is **re-measured** after the commit;
* R1 changes the GPU class' inference path to **`local_files_only=True`** (plus
  `HF_HUB_OFFLINE=1` / `TRANSFORMERS_OFFLINE=1` in the class env) and makes `@modal.enter()`
  **verify the cache against the recorded manifest** and **refuse to start** when it is
  incomplete. With `local_files_only=True` the hub client raises instead of downloading, so a
  GPU container in R3b or R4 makes **no** model request at all — and a wrong cache fails the
  container **closed** instead of quietly downloading.

The bound the estimate needs follows directly: the GPU class' per-container egress in R3b and
R4 is **0**, and the model bytes are billed **once**, to R2p, where they are a single
container's single download.

**The per-container caps.**

| Container class | per-container **payload** egress cap | how the cap is established |
|---|---|---|
| **sandbox CPU** — `verify_exploit_remote`, `verify_replay_remote` | **0** | the provider-enforced blocking declaration on the **exact** function, under the three conditions below |
| **GPU class** (R3b, R4) | **0** | `local_files_only=True` + the verified cache manifest; the inference itself is local to the container |
| **GPU class** (R2p prefetch) | `pinned_bytes × (1 + R_download)` | one container, one attempt, one pinned revision — the download plus its retry allowance |
| **persistence function** — `record_trajectory_remote` | **0 external** | by construction — it opens a file and commits the volume (`modal_app.py:700-712`) and makes no outbound request |

The table states the **payload** cap — the bytes the workload itself sends out. The
`protocol_allowance_GiB(c)` of the next paragraph is **added on top** of it for **every**
container of **every** class, including the classes whose payload cap is 0: **a payload zero
is not a total zero by implication.** The offline GPU path of R3b/R4 removes the *model
download* from those containers, and says nothing about their control-plane and volume
data-path traffic; the allowance is therefore not assumed to be zero there, and the
fail-closed rule below applies to it exactly as it applies to every other class — if the
allowance cannot be bounded for a class, that class's egress term is **unavailable** and the
step is **not dispatchable**.

**The sandbox class' zero is conditional, and the conditions are checkable before the
dispatch.** The pinned SDK (1.5.5) exposes `block_network` on both `App.function` and
`App.cls` ("Whether to block network access"), so R1 declares it on the two sandbox
functions. Three facts make the zero hold, and each is established **before** the first
dispatch, not after the run:

1. the declaration sits on the **exact** function the producer dispatches. The sandbox
   functions declare **no** `volumes=` (`modal_app.py:550-556`, `:582-588`), so they have no
   Modal data path to lose. The two classes that *do* mount the volume — the GPU class
   (`modal_app.py:74-80`) and the persistence function (`:695-700`) — **cannot** use the
   declaration, which is why their zero comes from their own construction and not from the
   blocking declaration;
2. the runtime path needs **no** external network: the whole toolchain — Foundry, solc
   0.8.19–0.8.28, forge-std v1.9.5, openzeppelin-contracts v5.0.2 — is installed **into the
   image at build time** (`sandbox/runner.py:49-69`), and the Foundry profile runs
   `offline = true` (`sandbox/runner.py:79`);
3. the **dispatch helper asserts** the declaration on the function object it is about to
   call, before the first dispatch of the step.

If any of the three cannot be established — the SDK exposes no way to assert the declaration,
or the blocking declaration breaks the function's own call path — the sandbox class is **not**
priced at 0 but at a **conservative per-container allowance**, recorded with its source and
its date; and if no allowance can be justified, the step is **not dispatchable**. The **R3
smoke's** billing read-back is the *post-run* check and is explicitly **not** the substitute
for this pre-dispatch bound: a post-run report can prove an overrun, it cannot prove a bound.

**The overhead is included, not assumed away.** The model file sizes are not the whole of a
billable egress: HTTP metadata requests, CDN redirects, protocol handshakes and retries are
billed too. They enter the bound in two forms:

* the **download allowance**: the prefetch's cap is `pinned_bytes × (1 + R_download)`, where
  `R_download` is the **declared maximum number of download attempts** of that step — an
  approval input with its source. If the client library's retry behaviour cannot be pinned to
  a number, a conservative `R_download` is used; if it cannot be bounded at all, **R2p is not
  dispatchable**;
* the **protocol allowance**: every runtime container carries the provider's control-plane and
  volume data-path traffic. `protocol_allowance_GiB(c)` is an approval input with its source
  and date. **If the provider's documentation does not establish that platform-internal
  traffic is excluded from the `Network Egress` rate class, the allowance is used
  conservatively rather than assumed to be zero** — and if it cannot be bounded at all, the
  affected step is **not dispatchable**.

**The step total — and why `max_containers` is not in it.**

```
cold_containers(c) ≤ invocations(c)              # the whole-step bound (D27): at most one cold start per invocation
network_egress_GiB(step) =
      Σ_c [ cold_containers(c) × payload_egress_cap_GiB(c) ]    # the payload itself
    + Σ_c [ cold_containers(c) × protocol_allowance_GiB(c) ]     # the protocol overhead
```

and the term is `Network_egress_rate × network_egress_GiB(step)` — the rate being an approval
input with its source and date, like every other rate in §8.2.5, and the quantity being the
bound above.

**`max_containers` is a concurrency cap, not a cumulative container-creation cap, and it is
therefore absent from this formula.** `max_containers` bounds the number of containers of a
class that may run **at the same time**. It does not bound the number of containers a class
may **create over the step**: a container that reaches the end of its `scaledown_window`,
scales down and is replaced by a new one for a later invocation is a **second** container,
and that replacement is fully within the concurrency limit of a class whose
`max_containers` is 1. A cumulative quantity therefore cannot be clamped by a concurrency
limit — the clamp would be *below* the true worst case, and a bound below the worst case is
not a worst case at all. The honest whole-step upper bound on the cold starts of class `c` is
the **invocation count** `invocations(c)`: one cold start per invocation is the worst case,
because a container may serve several invocations and then scale down before the next one
arrives. `min(invocations(c), max_containers_deployed(c))` is **not** an upper bound over the
step — for any class whose `scaledown_window` is non-zero it under-counts the containers that
were created over time, and therefore under-counts the egress.

Consequently `max_containers_deployed(c)` appears in this plan **only** as a **concurrency**
bound (D27): in the bound table above, in the dispatch helper's ceiling assertion
(`cap(c) ≤ max_containers_deployed(c)`) and in the wall-clock reasoning. It is never
multiplied into a cumulative quantity, and no cumulative quantity is ever clamped by it. The
two bounds are independent: `cold_containers(c) ≤ invocations(c)` is **provider-enforced**
(D27: `min_containers=0`, `buffer_containers=0`), and
`concurrent_containers(c) ≤ max_containers_deployed(c)` is a separate **provider-enforced**
fact about simultaneity.

The **protocol allowance** is multiplied by the same **cumulative** container count, not by
the concurrency: every container of the class carries the control-plane and volume data-path
traffic of its own lifetime, whether or not it runs concurrently with another container of
the class. The offline GPU path makes the **payload** egress of R3b/R4 zero — it says nothing
about the protocol and data-path traffic, so the allowance is **not** zero there by
implication, and the fail-closed rule below applies to it exactly as it applies to every other
class.

**Scope of the term.** The table prices the **runtime** egress of the step's containers. An
image **rebuild** — which is how the sandbox image's toolchain is fetched — happens outside
the step's containers and outside this estimate; if a rebuild is authorised as part of the
iteration, its egress is priced as a separate, separately recorded action, not folded into
the step's bound.

**The fallback, and why the prefetch is not optional.** Without the prefetch and the offline
path, the GPU class' honest per-container cap is the **pinned revision's byte size**, and the
step total is `cold_gpu_containers × pinned_bytes` — up to **32 model downloads** in R4. A
single revision of a 30B model is tens of GiB, so that bound exceeds any plausible ceiling:
**in that configuration R3b and R4 are non-dispatchable.** This is stated as a rule, not as a
worry: the prefetch + offline path is the **only** configuration in which the GPU steps have
a bounded egress, and R1 must establish it.

**The read-back is the provider's own report — and it is an audit, not the bound.** After the
step, the app session's `Network Egress` line is read from the provider's billing report —
the same report the existing CPU-smoke script already invokes
(`benchmarks/run_iteration19_cpu_smoke.py:177-189`). A line larger than the estimated bound
is an **overrun**: the app is stopped and the step is recorded as such, exactly like a spend
overrun (§8.2.5). The read-back **verifies** the pre-dispatch bound; it never **substitutes**
for it.

**An unbounded class is an unavailable estimate.** If any class's egress cannot be bounded —
the GPU revision cannot be pinned to a byte size, the prefetch cannot complete, the blocking
declaration cannot be established, the retry count or the protocol allowance cannot be
bounded — then the estimate is **unavailable** and the affected step is **not dispatchable**.
That is the same rule the memory term already follows (D26), applied to the egress term: a
missing bound is not a small bound.

Until all three classes declare them, the **memory term of the estimate has no upper bound at
all** — a scalar `memory=` is a request, and a container may exceed its request. The estimate
of §8.2.5 would then not be a worst case but an **open-ended** quantity, and the rule of
§8.2.5 applies to it verbatim: **the estimate cannot be bounded ⇒ the step is not
dispatchable.** That holds today for R2p, R3, R3b and R4 alike — the ceilings (Q5) are unset, *and*
the bounds are missing: no explicit limit, no bounded lifecycle, no enforced container count
(D27), no bounded volume (D28) and no bounded egress (D29).

Two invariants apply to all the compute steps:

* **A cap is a stop condition, not a target.** The step stops when the cap is reached; it
  never continues because the result is "almost" there.
* **Every step is a single attempt (D20).** "Exactly 1 attempt" means **one** invocation of
  the step in total — not one plus a hidden retry. There is no automatic retry: a step that
  fails ends there, the app is stopped and the failure is recorded. A retry is **not** a
  second attempt of the same step; it is a **new, separately named step** (for example `R3r`,
  `R3br`, `R4r`) with its own approval, its own monetary ceiling, its own pre-dispatch
  estimate and its own record in the approval table of the PR (below). The one-attempt rule
  is what makes the invocation maxima exact rather than approximate: **exactly 1** Modal
  invocation for R3, **at most 4** for R3b and **at most 96** for R4 (16 targets × the
  6-call per-target trace), with no second path (D20, §8.2.1 c, §8.2.2, §8.2.5).

The monetary ceilings of R2p, R3, R3b and R4 are **four separate numbers**, each attached to the
approval of the respective step. **Q5** (§11.2) holds all four of them — the prefetch R2p, the
GPU smoke R3b, the 16-target run R4, and, with its own, smaller number, the CPU smoke R3,
because a CPU container is a separate authorisation and not a free preliminary. None of the four
numbers is set by this plan, and a step whose ceiling is unset is **not dispatchable**: the
pre-dispatch gate below is the mechanism, and an unresolved ceiling means the gate cannot be
passed.

#### The pre-dispatch cost gate

A cap that is only checked *afterwards* is not a gate. Before any container is dispatched,
the step must pass a **pre-dispatch estimate gate** — three conditions, all of them checked
*before* the dispatch:

1. **The ceiling exists and is approved.** The step's monetary ceiling is a number, written
   down, and attached to that step's approval (**A-R2p**, **A-R3**, **A-R3b**, **A-R4**). The four
   ceilings are open question **Q5** (§11.2) and are **not yet set**; until the maintainer
   supplies and approves them, R2p, R3, R3b and R4 are **not dispatchable at all**. An unresolved
   ceiling is not a generous default — it is the absence of a budget, and this plan does
   not invent one.
2. **An estimate exists, and each of its inputs is named.** The estimate is the **worst case**
   the step can spend under its own caps. The **formula** is fixed by this plan; the
   **inputs** are recorded with their source and their date in that step's approval record:

   ```
   estimate(step) =
       GPU_rate             × gpu_container_seconds(step)                 [input 1]
     + CPU_rate             × sandbox_core_seconds(step)                  [input 2]
     + Memory_rate          × sandbox_GiB_seconds(step)                   [input 3]
     + CPU_rate             × persistence_core_seconds(step)             [input 4]
     + Memory_rate          × persistence_GiB_seconds(step)              [input 5]
     + CPU_rate             × gpu_container_core_seconds(step)           [input 6]
     + Memory_rate          × gpu_container_GiB_seconds(step)            [input 7]
     + Volume_storage_rate  × volume_GB_months(step)                     [input 8]
     + Network_egress_rate  × network_egress_GiB(step)                   [input 9]
   ```

   with, for every container class `c`:

   ```
   T_billable(c)   = startup_bound(c) + execution_bound(c) + idle_bound(c)
   core_seconds(c) = cpu_limit(c) × T_billable(c) × containers(c)      # upper bound
   GiB_seconds(c)  = memory_limit(c) × T_billable(c) × containers(c)   # upper bound
   containers(c)   ≤ invocations(c)      # provider-enforced: min_containers=0, buffer_containers=0 (D27)
   concurrent(c)   ≤ max_containers(c)   # provider-enforced: the deployment's CONCURRENCY cap — not a cumulative
                                         # container-creation cap, so it never clamps a cumulative quantity (D27, D29)

   volume_GiB(step)         = baseline_GiB + incremental_GiB(step)          # measured + bounded (D28)
   T_store(step)            = T_exec(step) + T_post_exec_to_publication(step) + T_retention(step)  # bounded duration (D28)
   months(step)             = 1 + ceil(T_store(step) / 28 days)             # conservative calendar months (D28)
   volume_GB_months(step)   = volume_GiB(step) × months(step)               # the retention rule (D28)
   cold_containers(c)       ≤ invocations(c)        # the whole-step bound (D27): one cold start per invocation at worst;
                                                          # max_containers is concurrency-only and does NOT clamp this (D29)
   network_egress_GiB(step) = Σ_c [ cold_containers(c) × payload_egress_cap_GiB(c) ]  # the payload (D29)
                            + Σ_c [ cold_containers(c) × protocol_allowance_GiB(c) ]  # the overhead (D29)
   ```

   `cpu_limit` and `memory_limit` are the **explicit** limits R1 adds (the R1 resource
   precondition above, D26) — the declared requests are the *floor* of the bill, never its
   ceiling (§5.6 g) — and `T_billable` is the container's whole life: startup + execution +
   idle retention, all of it billed (§5.6 g). The container count, the volume quantity and the
   egress quantity are the three bounds of the subsections above: the container count is
   **provider-enforced** by the autoscaler policy (D27), the volume quantity is **measured and
   bounded by construction** over a **bounded duration** (D28), and the egress quantity is
   **per-container policy-bound or measurement-bound** and summed over the step's containers
   (D29).

   | # | Input | What it prices | Where it comes from | Status |
   |---|---|---|---|---|
   | 1 | `GPU_rate` | the H100 seconds of the GPU calls (`generate_solidity_exploit`, `refine_solidity_exploit`) — over the **container's** billable lifetime, not the function's timeout | the provider's published H100 rate | **input to the approval** — never a repository constant |
   | 2 | `CPU_rate` | the CPU core-seconds of the **sandbox** functions (`verify_exploit_remote`, `verify_replay_remote`), at their **explicit CPU limit** after R1 (today: a 2.0-core request under the default `request + 16` limit, i.e. 18.0 cores) | the provider's published Function CPU rate (physical cores; 1 core = 2 vCPUs) | **input to the approval**; the *bound* it multiplies is R1's explicit limit (D26) |
   | 3 | `Memory_rate` | the memory GiB-seconds of the **sandbox** containers, at their **explicit hard memory limit** after R1 (today: a 2048 MiB request with **no** limit) | the provider's published memory rate | **input to the approval**; the bound is R1's explicit limit — **without it this term is unbounded** (D26) |
   | 4 | `CPU_rate` | the CPU core-seconds of the **persistence function** `record_trajectory_remote`, at its **explicit CPU limit** after R1 (today: a 0.125-core request under the default 16.125-core limit). It is **not** covered by input 2: it declares no `cpu=`, so it is neither at the sandbox's request nor free | the **same published Function CPU rate** as input 2 — there is **no separate persistence rate class**, because the provider publishes none (§5.6 g, D25) | **input to the approval**; the *bound* is R1's explicit limit (D26) |
   | 5 | `Memory_rate` | the memory GiB-seconds of the **persistence** container, at its **explicit hard memory limit** after R1 (today: a 128 MiB request with **no** limit) | the **same published memory rate** as input 3 | **input to the approval**; the bound is R1's explicit limit — **without it this term is unbounded** (D26) |
   | 6 | `CPU_rate` | the CPU core-seconds of the **GPU containers' own** CPU — `ProductionAuditAgent` declares `gpu=…` and **no** `cpu=` (`modal_app.py:74-80`), so it too runs on the platform default request (§5.6 g) | the **same published Function CPU rate** as input 2 | **input to the approval**; the bound is R1's explicit limit (D26) |
   | 7 | `Memory_rate` | the memory GiB-seconds of the **GPU containers** — the H100 line and the memory line are separate charges on the same container | the **same published memory rate** as input 3 | **input to the approval**; the bound is R1's explicit limit — **without it this term is unbounded** (D26) |
   | 8 | `Volume_storage_rate` | the persistent volume's **storage** — the bytes stored in `aegis-model-cache` over the step's **bounded storage duration**, **including the execution, the post-execution interval before the publication and the post-run retention** (D28). The write/commit of the persistence function (`modal_app.py:709-711`) contributes **bytes stored**, not a second charge: the provider publishes **no** commit fee, so there is no commit line in the estimate (§8.2.5) | the provider's published volume-storage rate (per GiB-month, with its published free allowance recorded but **not** netted out) | **input to the approval**; the *quantity* it multiplies is the measured baseline plus the bounded increment, **both** priced over the same bounded duration `(1 + ceil(T_store / 28 days))` months, where `T_store = T_exec + T_post_exec_to_publication + T_retention` (D28) |
   | 9 | `Network_egress_rate` | the **network egress** of the step — the payload each container sends out plus the protocol overhead, at a **per-container** cap summed over the step's containers: 0 for the sandbox class under the provider-enforced blocking declaration (verified before the dispatch), 0 for the GPU class in R3b/R4 (offline mode + the verified cache manifest), `pinned_bytes × (1 + R_download)` for the GPU class in the **R2p prefetch**, 0 external for the persistence function — all four are **payload** caps (D29, §8.2.5) — plus a `protocol_allowance_GiB(c)` per container, which is added **on top of every one of them**, including the GPU class' offline containers in R3b/R4, because a payload zero is not a total zero by implication. This is a **separate rate class** of the provider's, and the published app session already carries a non-zero `Network Egress` line (`$2.6E-7`) | the provider's published network-egress rate (per GiB, with the plan-level allowance recorded but **not** netted out) | **input to the approval**; the *quantity* it multiplies is the per-container **payload** cap + the per-container `protocol_allowance_GiB(c)`, each multiplied by the step's **cold containers**, whose count is bounded by the **invocation count** — `cold_containers(c) ≤ invocations(c)` — and is **not** clamped by `max_containers_deployed(c)`, which is a concurrency cap and not a cumulative container-creation cap (D29); **without it this term is unbounded** (D29) |

   **There is no `Persistence_rate`.** The provider publishes CPU and memory rates by resource
   class; the persistence function is a Function, so it is priced with the **same** CPU and
   memory rates as the other Functions (inputs 4 and 5), plus the volume's storage rate
   (input 8). The historical per-function split of the published app-session aggregate stays
   unresolved (§5.6 g) — that is an **attribution** limitation of the old evidence, not a
   missing price, and the estimate does not depend on it. There is likewise **no commit fee**
   (input 8) and **no separate egress rate per function** (input 9) — egress is one published
   rate class for the data a container sends out, whoever sends it.

   The **call counts** come from the per-target trace table above and are fixed by this plan:
   R3 = **1** sandbox-CPU call; R3b = **≤ 4** (1 GPU + ≤ 2 sandbox-CPU + ≤ 1 persistence);
   R4 = **≤ 96** (≤ 32 GPU + ≤ 48 sandbox-CPU + ≤ 16 persistence). They count **invocations**;
   because Modal reuses a container for several inputs (§5.6 g), the **container count is at
   most** the invocation count — and that bound is **provider-enforced** once R1 declares
   `min_containers=0` and `buffer_containers=0` (D27): with no warm pool and no idle buffer,
   every billed container serves at least one invocation. The estimate uses the invocation
   count as the conservative bound. Each call is additionally bounded by the step's wall-clock
   budget and by its own container's `T_billable` — **not** by the function's timeout, which
   covers the execution phase alone (§5.6 g). Because every step is a single attempt (D20),
   there is **no attempt multiplier**: the estimate covers the one attempt, and a retry — a
   separately named step — needs its own estimate against its own ceiling.

   **The persistence call is priced as compute, at the published Function rates.** It is a
   container of its own (§5.6 g): the estimate prices it with **inputs 4, 5 and 8**. If the
   bounds those inputs multiply are not in place — i.e. if R1 has not declared the explicit
   limits — the estimate is **unbounded**, and the step is **not dispatched**: the same
   "estimate unavailable ⇒ no dispatch" rule that applies to every other input.

   No rate is hardcoded in the repository, for the same reason the producer does not hardcode
   cost estimates (`benchmarks/adapters.py:19` — "No hardcoded cost estimates: unmeasured runs
   report cost_usd as None"; the published `summary.json` carries `cost_status: "unmeasured"`
   and `cost_usd: null`, `benchmarks/artifacts/run_1794209615_70f5d22/summary.json:167-168`).
3. **The estimate is at or below the ceiling.** If `estimate > ceiling`, the step is **not
   dispatched**: either the ceiling is raised by a new, explicit approval, or the compute cap
   (container count, wall-clock budget) is lowered until the worst case fits under it. A retry
   step is not covered by this gate: it has its own ceiling, its own approval and its own
   estimate at or below that ceiling.

**If the estimate is unavailable, the step does not start.** "Unavailable" means: the
provider publishes no rate for the requested resources, the workspace's billing data cannot
be read, the rate cannot be obtained from the provider's own documentation at dispatch
time, **the provider enforces no ceiling on a resource the step uses** (a request is not a
limit, §5.6 g), **the billable lifetime of a container is not bounded** (no explicit
`startup_timeout` / `scaledown_window`, so the startup and the idle retention are not in
the bound), **the container count is not provider-enforced** (no `min_containers=0` and no
`buffer_containers=0`, so the provider may bill warm or buffered containers that carry no
invocation, D27), **the volume quantity cannot be measured or bounded** (the baseline
listing fails, the increment has no cap, **or the storage duration is not bounded** — no
declared wall-clock budget and no finite ceiling, **or no post-execution deadline is declared**
before the publication, D28), **a class's egress cannot be bounded**
(the GPU revision cannot be pinned, the prefetch cannot complete, the blocking declaration
cannot be established, the retry count or the protocol allowance cannot be bounded, D29), or
the estimate command fails. In every one of those cases the step is recorded
as **"not dispatched — estimate unavailable"**, with the reason — never as "dispatched, cost
unknown, we will see". The repository already holds the pattern for this: the CPU smoke's
billing collection returns the provider's own line items or an explicit `NOT_AVAILABLE` with
the exact reason and the failed command, and states that the value "is never estimated"
(`benchmarks/run_iteration19_cpu_smoke.py:169-204`).

**This applies in particular to the resource bounds — not to the rates.** Today no container
class declares a hard memory limit, so the memory terms of the estimate (inputs 3, 5 and 7)
have **no upper bound**, and the CPU terms (inputs 2, 4 and 6) are bounded only by the
provider's default `request + 16` rule, which moves with the request rather than being
declared. The **container count** (the multiplier of inputs 1–7) is bounded only by
invocation arithmetic, because no class declares `min_containers`, `buffer_containers` or
`max_containers`; the **volume quantity** (input 8) has neither a measured baseline nor a
capped increment nor a bounded duration — neither a bounded execution budget nor a bounded
post-execution interval; and the **egress quantity** (input 9) is not bounded
at all — the GPU class' model download is a **per-container** cost that every cold GPU
container would pay, and the plan allows up to 32 of them in R4 (D29). The estimate
for **R2p**, **R3**, **R3b** and **R4** is therefore **unbounded**, and an unbounded estimate is an
unavailable estimate: **none of the four steps is dispatchable.** R1's explicit
request/limit pairs and explicit lifecycle bounds (the R1 resource precondition above, D26),
its autoscaler policy (D27), its volume policy (D28) and its egress policy (D29) are what
turn the estimate into a worst case.

The **historical** per-function attribution stays unresolved — the canonical run's
`$0.03001687` CPU line covers the GPU containers' CPU, the 32 sandbox-CPU calls and the 2
persistence calls together, and the export carries no function dimension (§5.6 g). That is a
limitation of the **old** evidence, not of the estimate: the estimate prices the future run
with the published Function rates and needs no per-function share of an old aggregate, and
the published evidence publishes the app-session total — the only level the provider's
export resolves (§4.4, §10.3).

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
| **A-R2p** | R2p only: the model-cache prefetch — **one CPU container**, one attempt, the pinned revision's download, its own ceiling — and the pre-dispatch estimate at or below that ceiling, computed against the explicit limits and lifecycle bounds of the prefetch container, against the deployed autoscaler policy (D27), against the **measured volume baseline** and the **pinned revision's byte size** over the **bounded storage duration** — the execution budget, the post-execution deadline and the retention (D28) — and against the **download allowance** `pinned_bytes × (1 + R_download)` plus the protocol allowance (D29). Without them the estimate is **unbounded**, and the approval cannot be granted | R3, R3b, R4 — the prefetch populates a cache; it is not a benchmark run |
| **A-R3** | R3 only: the sandbox-CPU container, one target, one hypothesis, the CPU ceiling — and the pre-dispatch estimate at or below that ceiling | R2p, R3b (GPU), R4 (16 targets, H100) |
| **A-R3b** | R3b only: one GPU inference call for one target, the GPU hard maximum cost — and the pre-dispatch estimate at or below that ceiling, computed against the **explicit** CPU and memory limits and the **explicit** lifecycle bounds that R1 declares for the GPU, the sandbox and the persistence classes (§8.2.5, D26), against the **deployed autoscaler policy and the dispatch helper's per-step caps** (D27), against the **measured volume baseline and capped increment over the bounded storage duration** — the execution budget, the post-execution deadline and the retention (D28) — and against the **per-container egress bounds** (D29). Without them the estimate is **unbounded**, and the approval cannot be granted | R2p, R3, R4 |
| **A-R4** | R4 only: the 16-target H100 run, the Q5 ceiling **and R4's wall-clock budget and post-execution deadline** (D28) — and the pre-dispatch estimate at or below that ceiling, computed against the same explicit limits, lifecycle bounds, autoscaler policy, volume policy and egress policy (§8.2.5, D26–D29) | R2p, R3, R3b, and any retry step of either — a retry is a separate step with a separate approval (D20) |

The rules:

1. **Approval for R4 does not approve R2p, R3 or R3b; approval for R3 does not approve R3b; and
   approval for R3b does not approve R2p.** Each step is authorised separately, in writing, with
   its own ceiling attached.
2. **Approval for R3b does not approve R4.** R3b exists to prove the inference plumbing
   *before* the expensive run; if it fails, the sequence stops at R3b (§8.3) and R4 needs a
   **new** approval, not the old one. **Approval for R2p does not approve R3b either** — the
   prefetch populates a cache and proves nothing about the inference path (§8.3).
3. **One approval covers one attempt.** The approval of a step covers exactly the attempt its
   cap states — and the cap states **one**, because no step is retried automatically (D20).
   There is no approval of the form "the step and a second try if it fails": a retry is a
   **new, separately named step** (for example `R3r`) with its own approval (for example
   `A-R3r`), its own ceiling, its own pre-dispatch estimate and its own row in the approval
   table of the PR.
4. **The approval record is part of the PR.** The PR of the regeneration iteration records,
   per step: the approver, the date, the approved ceiling, **the step's wall-clock budget**
   and **the step's post-execution deadline** (D28), the pre-dispatch estimate with
   the rate source it was computed from — **and, for each of the estimate's nine inputs
   (§8.2.5), the source and the date of that input** — and the actual spend read back from
   the provider. The record also carries the **bounds**, not only the rates: the effective
   autoscaler settings read back before and after the step and the step's own per-class caps
   from the dispatch helper (D27), the measured volume
   baseline, the **bounded storage duration** (`T_exec`, `T_post_exec_to_publication`,
   `T_retention`) and the post-step
   re-measurement with the cleanup event (D28), and the
   provider's `Network Egress` line for the app session — an **audit** of the egress bound,
   never its substitute (D29). A step without that record
   did not run.
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

The chain R1 → R2 → R2p → R3/R3b → R4 advances HEAD: R2 adds the negative tests, R2p, R3 and R3b are
run steps whose transcripts land on the branch, and R4's run directory is named after the SHA
that happened to be checked out at that moment. If the run were executed from the branch head
of that moment, the manifest would record the *tests* commit — a SHA that is not the commit
the producer was written in, and not the commit the closure's producer-immutability check
(P6.14) is about.

**The contract: the run executes from a detached worktree pinned at the producer commit.**

1. **R1 and R2 together produce the producer commit `P`, and `P` is sealed after R2.**
   `P` is the commit that closes the producer surface: the last commit that touches
   `modal_app.py` (repository root), `benchmarks/adapters.py`,
   `benchmarks/benchmark_runner.py` or the validators. R2 adds the negative tests T1–T16, so
   `P` is the **R2** commit — or any commit that contains both changes — and it is sealed
   *before* the first container is dispatched. No commit after `P` may touch a producer path
   — that is what makes P6.14's diff empty (§9.3) and what makes the invalidation rule of
   item 10 unambiguous.
2. **R2p, R3, R3b and R4 are executed from a detached worktree at `P`, and so are the two steps
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
R2p (model-cache prefetch, separately authorised) ──> R3 (CPU smoke) ──> R3b (GPU inference smoke) ──> R4 (run)
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

**R2p sits before every GPU step on purpose.** The GPU class' `@modal.enter()` downloads the
model whenever the cache is cold, and it runs on **every** container start — so without a
prefetch, the model's bytes are a **per-container** egress cost that up to 32 cold containers
in R4 would each pay, and the egress bound of the GPU steps is not a worst case but a wish
(D29). The prefetch pays that cost **once**, under its own approval and its own ceiling, and
after it the GPU containers load the model locally (`local_files_only=True`) and fail **closed**
on an incomplete cache. R2p is not a benchmark run: it produces no artifact and proves nothing
about the inference path, which is why it has its own, separate approval.

R3b sits **before** R4 on purpose: the inference plumbing is the one part of the provenance
contract that R3 cannot exercise, and R4 is the expensive step. Paying for 16 GPU targets
before the inference path is known to work would spend the entire budget to produce
unpublishable artifacts.

**A failed smoke ends the sequence.** A smoke that fails its gate stops the regeneration
there (§8.2.5): the sequence does not continue into R4 with a producer that is known to be
broken, and R4 requires its own approval in any case. The same holds for the prefetch: a
failed R2p ends the sequence before R3b, and a retry is a new, separately named step. There is
**no automatic retry** of a
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
2. **Model-cache prefetch (small cost, own approval):** one CPU container that downloads the
   **pinned revision** of the model into the volume's cache and commits it — this is **R2p**
   (§8.2, D29). It exists because the GPU class' `@modal.enter()` downloads the model whenever
   the cache is cold, and it runs on **every** container start: without the prefetch, the
   model's bytes are a **per-container** egress cost that up to 32 cold containers in R4 would
   each pay, and the GPU steps' egress has no worst case. The prefetch has its own ceiling,
   its own approval **A-R2p** and its own pre-dispatch estimate gate (§8.2.5), and it is a
   **single attempt** (D20). Its output is the **file manifest** of the pinned revision and
   the re-measured volume — after it, the GPU containers load the model locally and download
   nothing.
3. **CPU plumbing smoke (small cost):** one target, executed through the producer's own path
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
4. **Inference-plumbing smoke (minimal GPU cost):** one target with the published inference
   configuration, exercising the `inference` stage and resolving its provider-issued identities
   — this is **R3b** (§8.2.2), and it needs its **own explicit authorisation** **A-R3b** with
   its cap fixed before the first call (§8.2.5). It is a **single attempt** (D20): dispatched
   once, never retried automatically, and any failure ends it. The **refinement branch is
   switched off** for this step (§8.2.2 a) — the smoke proves the inference plumbing, not the
   refinement branch, and it must not pay for a second GPU call it did not plan for.
5. **Full run (cost):** the 16 targets, `modal_h100`, `--hypotheses=3`, executed from the
   detached worktree at `P` (§8.2.6) under the approval **A-R4** and the ceiling of Q5. The
   **refinement branch is enabled** here, as in the published run — the published
   configuration refined on 14 of 16 targets (§5.6 b) — so the run may make up to **6** Modal
   invocations per target and **96** in the run (§8.2.5).
6. **Client-side correlation:** for every stage, resolve the provider-issued
   `container_id` from the `function_call_id` the worker observed, using
   `call_graph_inputs` → `containers_of_app` → `task_app_id`, with the last one as an
   independent cross-check. If the provider does not answer, the field is recorded
   `NOT_AVAILABLE` with the provider's own reason — **never** a synthetic id (§6.6 T5).
7. **Billing export:** export the raw billing line items for the run's window
   (`modal app billing` / the workspace's billing export) into
   `modal_billing_report_raw.json`. **Only if a new billing window is opened** — otherwise the
   raw export, and its digest in the join table, stay exactly as they are (§4.4, §7.3).
8. **Join table:** regenerate schema 3.0.0 from the raw export; target-level costs stay
   `null` unless an exact, unique provider join exists.

### 10.3 Cost controls

| Control | Value |
|---|---|
| Per-step ceilings | **four separate numbers** — the prefetch ceiling of **R2p**, the CPU ceiling of **R3**, the GPU hard maximum cost of **R3b**, and the ceiling of **R4** (§8.2.5). All four are **not yet set** — open question **Q5** (§11.2); a step whose ceiling is unset is **not dispatchable** |
| Per-step wall-clock budgets | every step declares **two** wall-clock declarations in its approval record: the **execution budget** (`T_exec`) and the **post-execution deadline** (`T_post_exec_to_publication`, D28). The execution budget is the step's execution bound, and through `T_exec ≤ ceiling / burn_rate` it is also the **second, independent bound on the storage duration** (D28); the post-execution deadline bounds the interval between the end of the compute step and the publication, during which the run's bytes stay stored and the retention clock has not yet started. **R4 declares neither today** — its stop condition is the monetary ceiling alone — so R4's volume term is unavailable and **R4 is not dispatchable** until the maintainer supplies them (Q5). **No step declares a post-execution deadline yet**, so on that ground alone the volume term of all four steps is unavailable (D28) |
| Pre-dispatch estimate | every compute step passes the estimate gate of §8.2.5 **before** the first container: a numeric ceiling approved for that step, a worst-case estimate at or below it, and a recorded rate source. An unavailable estimate ⇒ **no dispatch** |
| Estimate source | the provider's published rate for the declared resources — an input to the approval record, never a constant in the repository (`benchmarks/adapters.py:19`; `cost_status: "unmeasured"` in the published `summary.json:167`). The estimate has **nine named inputs** (§8.2.5). The **rates** are all published — CPU, memory, GPU, volume storage **and network egress**; the **bounds** those rates multiply are not, until R1 declares the explicit request/limit pairs, the explicit lifecycle bounds, the autoscaler policy, the volume policy and the egress policy. Until then the estimate is **unbounded**, and R2p, R3, R3b and R4 are **not dispatchable** (§8.2.5, D26–D29) |
| Estimate formula | `GPU_rate × gpu_container_seconds + CPU_rate × sandbox_core_seconds + Memory_rate × sandbox_GiB_seconds + CPU_rate × persistence_core_seconds + Memory_rate × persistence_GiB_seconds + CPU_rate × gpu_container_core_seconds + Memory_rate × gpu_container_GiB_seconds + Volume_storage_rate × volume_GB_months + Network_egress_rate × network_egress_GiB` (§8.2.5), where every container term is `limit × T_billable`, `T_billable = startup_bound + execution_bound + idle_bound`, the container count is **at most** the invocation count — a bound the autoscaler policy makes **provider-enforced** (§5.6 g, D27) — the volume quantity is the measured baseline plus the capped increment over the **bounded storage duration** `T_exec + T_post_exec_to_publication + T_retention` (D28), and the egress quantity is the **per-container payload cap + the per-container protocol allowance**, each multiplied by the step's **cold containers**, whose count is bounded by the **invocation count** and is **never** clamped by the concurrency ceiling `max_containers` (D27, D29). The persistence function is priced with the **same published Function CPU and memory rates** as the other Functions — there is **no separate persistence rate class** — plus the volume's storage rate (D25); there is **no commit fee** and **no per-function egress rate** |
| Resource profile and lifecycle bounds | before any compute step is dispatched, every container class must declare `cpu=(request, limit)`, `memory=(request, limit)`, `startup_timeout` and `scaledown_window` — the **R1 resource precondition** (§8.2.5, D26). A **request** is not a limit, and a **timeout** is not the billable lifetime (§5.6 g) |
| Autoscaler policy | every container class declares `min_containers=0`, `buffer_containers=0` and a deployed `max_containers` equal to the **union** of the steps' caps for that class (sandbox 48, GPU 32, persistence 16) — the **R1 autoscaler policy** (§8.2.5, D27). The deployed configuration **never changes between the steps**: the repository contains **no mutating autoscaler call**, so no cap can be raised and no stale override can survive; the **per-step** cap is enforced by the **dispatch helper** (invocation budget + concurrency gate + ceiling assertion) from the step's approval record, and the effective settings are **read back** — with the **no-argument** `update_autoscaler()`, which changes nothing — before the first container and again after the step, and both readings are recorded. Without this the container count is an arithmetic hope, not a provider-enforced bound, and the step is **not dispatchable** |
| Volume storage bound | the billable volume quantity is the **measured baseline** of `aegis-model-cache` plus the **capped increment** (one capped trajectory file per dispatched persistence call; the pinned model revision's bytes in the **prefetch step R2p**), multiplied by the **bounded storage duration** — `T_store = T_exec + T_post_exec_to_publication + T_retention` (the post-execution deadline covers the validation, the report, the commit, the review and the publication; `T_retention` = 30 days after the publication, the same 30 days on the abort path), priced as `1 + ceil(T_store / 28 days)` months (§8.2.5, D28). The **baseline** is priced for the same bounded interval; **all run-created bytes are counted until the deletion is verified**. Every step declares a **wall-clock budget** and a **post-execution deadline**, and `T_exec ≤ ceiling / burn_rate` bounds the execution budget a second time. An unmeasurable volume, an unbounded duration — of the execution or of the post-execution interval — and an exceeded cap are fail-closed stops, not small ones; a **commit is not a fee** — the provider publishes none |
| Network egress | every container class has a **per-container** egress bound, summed over the step's containers (§8.2.5, D29): the sandbox class at **0** under the provider-enforced blocking declaration (established before the dispatch — the declaration, the source-level proof and the dispatch helper's assertion — with the R3 smoke as the empirical confirmation), the GPU class at **0** in R3b/R4 (offline mode + the verified cache manifest), the GPU class in the **prefetch step R2p** at `pinned_bytes × (1 + R_download)`, the persistence function at **0 external** — those four are **payload** caps — plus a `protocol_allowance_GiB(c)` per container for the control-plane and volume data-path traffic, used conservatively unless the provider's documentation excludes platform-internal traffic from the egress rate class. The step total multiplies both by the step's **cold containers**, whose count is bounded by the **invocation count** (`cold_containers(c) ≤ invocations(c)`) and is **never** clamped by `max_containers_deployed(c)`: that value is a **concurrency** ceiling, not a cumulative container-creation cap, and a clamp by it would sit below the step's true worst case (D27, D29). The protocol allowance applies to **every** container, including the GPU class' offline containers in R3b/R4 — a zero payload cap is not a zero total. The estimate carries the term as its **ninth input**; the provider's own `Network Egress` line for the app session is the **post-run audit** of that bound, never its substitute. A class whose egress cannot be bounded makes the estimate unavailable, and the step is **not dispatchable** |
| Actual spend | the provider's own billing report after the run (`benchmarks/run_iteration19_cpu_smoke.py:177-189`), compared with the ceiling; an overrun aborts the step (`modal app stop`) and is recorded as an overrun |
| Per-step approvals | **A-R2p**, **A-R3**, **A-R3b**, **A-R4** — one per step, each with its own ceiling (§8.2.5). No approval implies another: the approval of R4 approves R4 and nothing else |
| Per-step caps | **exactly 1 attempt** per step, no automatic retry (D20): R2p = **1** CPU container (the prefetch), R3 = **1** Modal invocation (sandbox CPU), R3b = at most **4** (1 GPU + ≤ 2 sandbox-CPU + ≤ 1 persistence function; the refinement branch is switched off, §8.2.2 a — **6** against the pre-R1 producer, which is not authorised), R4 = one authorised run of 16 targets making at most **96** Modal invocations (**≤ 32** GPU + **≤ 48** sandbox-CPU + **≤ 16** persistence function); the published run's own measured trace was 64 (**30** GPU + **32** sandbox-CPU + **2** persistence function) (§8.2.5) |
| Target cost attribution | `null` + `UNATTRIBUTED_NO_INVOCATION_LEVEL_JOIN` unless a proven join exists — the existing policy already prevents a target cost from being invented |
| Aggregate allocation | `FORBIDDEN` (`attribution_policy.aggregate_bucket_allocation`) — no aggregate bucket may be spread over targets |
| App-session granularity | the app-session total is the only cost that may be published |
| Pre-flight | the prefetch (step 2) and the smoke run (step 3) happen **before** the 16-target run and must be reviewed; a failed prefetch or a failed smoke ends the sequence (§8.3) |
| GPU | `H100` only where the original run used it; **sandbox CPU** (request 2.0 cores / 2048 MiB) for the EVM-sandbox and replay stages; the **persistence function** on its own default profile — no `cpu=`, no `memory=`, request 0.125 cores / 128 MiB, default CPU limit 16.125 cores, **no hard memory limit**, `timeout=60`, persistent volume attached (§5.6 g). All three classes are **unbounded** until R1 declares their explicit limits and lifecycle bounds (D26) and its autoscaler, volume and egress policies (D27–D29) |
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
| **D16** | **No compute step is dispatched without a pre-dispatch cost estimate at or below its own approved ceiling. If the estimate is unavailable — and an estimate over unbounded resources is unavailable — the step does not start.** The estimate covers the step's **single** attempt (D20); a retry step needs its own estimate against its own ceiling. The monetary ceilings — R2p, R3, R3b, R4 — remain **Q5** (§11.2) and are **not** set by this plan; until they are supplied and approved, all four steps are undispatchable. **Independently of the ceilings**, the estimate is **unbounded** today: no container class declares a hard memory limit, no class declares an explicit startup or idle bound, the default CPU limit moves with the request, no class declares an autoscaler policy that keeps the container count at the invocation count, no volume baseline was measured, no step declares a wall-clock budget, no step declares a post-execution deadline and no class's egress is bounded (D26–D29) — so **none of the four steps is dispatchable even if its ceiling were set today**. | A cap that is only checked after the spend is not a gate, and R3b spends GPU credits before the full-run ceiling exists, so it needs a ceiling, an approval and an estimate of its own. The repository deliberately has no cost estimator (`benchmarks/adapters.py:19`; `cost_status: "unmeasured"`), so the estimate has to come from the provider and be recorded with its source — it cannot be invented here (§8.2.5). |
| **D17** | **R3 runs the producer's own `execute_target()` and takes the adapter's candidate-generator branch, so the inference stage is not attempted.** The mechanism is the `candidate_generator` parameter the production adapter already has (`benchmarks/adapters.py:1596`, stored at `:1603`, used at `:1783-1784`) — not a separate smoke app, and not a `modal_cpu` provider, which does not exist in the code. R1 introduces the **fixture and its loader**, not a bypass mechanism. | Only the producer writes the §5 stage block (`benchmarks/adapters.py:2377-2411`); the dedicated CPU app (`benchmarks/modal_cpu_smoke_app.py`) produces a single-function identity record and stays a pre-flight check. The candidate generator short-circuits the provider dispatch **before** the GPU call (`:1783` vs `:1785-1792`), and the refinement loop cannot fire because it requires `candidate_generator is None` (`:1838`), so R3 makes exactly one Modal call, and it is a CPU one. The stage block is always complete — all six keys are written (`:2377-2409`, §5.6 d) — so the attempt flag inside it is what distinguishes "not attempted" from "attempted and failed" (`evidence_integrity.py:1829-1836`, `:608-614`) (§8.2.1, §10.2). |
| **D18** | **The producer surface is sealed at `P`, and the run is bound to the bytes of `P`.** Every execution step and every step that judges the run's bytes happens in the detached worktree at `P`; the executed producer bytes are verified by digest; and any commit after `P` that touches a producer path **invalidates the run** and requires a fresh capture. | The manifest's SHA binds a commit; a digest binds the bytes, and only the second one rules out "the code that ran is not the code that was named". A producer-changing commit between the capture and the closure is detected by P6.14's diff, and the consequence is fixed in advance — a new capture, not a re-labelled one (§8.2.6, §9.3). |
| **D19** | **R3's candidate is a checked-in, non-breaching fixture — a negative control — and R3 claims only the EVM-sandbox stage.** The fixture is never presented as model output, is written outside `benchmarks/evidence/`, and its digest is recorded with the smoke. R3 records `independent_replay.attempted = false` and proves nothing about the replay stage. | A plumbing smoke needs a candidate that costs no GPU credits and cannot fabricate a finding. A model candidate would make R3 a paid inference test — that is R3b. A breaching candidate would make the replay branch fire (`adapters.py:1882`) and turn a plumbing smoke into an accidental benchmark run. The producer enters that branch only on `INVARIANT_BREACH_UNREPLAYED`, so a non-breaching fixture keeps the smoke deterministic and its stage matrix fixed (§8.2.1 b, c). |
| **D20** | **Every compute step is a single attempt.** R3 is dispatched exactly once — worst case **1** Modal invocation; R3b exactly once — worst case **4** Modal invocations under the refinement-disabled producer of D22 (**6** against the pre-R1 producer), all of them inside that one attempt; R4 as one authorised run of its 16 targets, at most **96** Modal invocations (D23). There is **no automatic retry**: a failure ends the step, and a retry is a **new, separately named step** (for example `R3r`, `R3br`, `R4r`) with its own approval, its own ceiling, its own pre-dispatch estimate and its own row in the approval record. | A "1 invocation" description next to a "≤ 2 attempts" cap is not an execution contract but two contradicting ones, and a cap that silently permits a second attempt is a cap with two budgets. Settling the semantics in one place — one attempt per step — keeps the invocation maxima exact (1, 4 and 96, with no hidden second path), keeps the cost ceiling meaningful and keeps the pre-dispatch estimate equal to the worst case (§8.2.1 c, §8.2.2, §8.2.5, §10.3). |
| **D21** | **The closed-loop refinement is a real part of the producer's contract, and the plan models it explicitly.** A target makes **up to six** Modal calls — **2 GPU + 3 sandbox-CPU + 1 persistence function** (§5.6 a) — and the published bytes prove the branch fires: 14 of the 16 published artifacts record `candidates_generated = 2`, while their `modal_functions` name only two functions (§5.6 b). These are **invocation** counts; because Modal reuses a container for several inputs, the invocation count is an **upper bound** on the number of containers (D27), and the estimate of §8.2.5 uses it as such. | A cap that counts one inference call per target is wrong about the code that runs; the plan cannot specify an invocation budget, an artifact schema and a cost estimate while ignoring a branch that two thirds of the published targets took. The published run made **64** calls, not the 48 the earlier draft implied. |
| **D22** | **R3b runs with the refinement branch disabled** — through a producer switch that **R1 adds** (`enable_refinement: bool = True`, the default being today's behaviour, so R4 is unaffected). R3b's worst case is therefore **4** invocations, and the negative test **T13** proves the R3b configuration cannot dispatch `refine_solidity_exploit`. Against the **pre-R1** producer the worst case is 6, and this plan authorises no pre-R1 R3b. | The refinement is a **second GPU call** whose trigger is the model's *failure* — the likely outcome of a smoke — so leaving it on would make R3b's cap and its stage matrix outcome-dependent in a second, unplanned way. R3b exists to prove the **inference** plumbing before the paid run; the refinement path is covered at no cost by the mocked trace test (**T16**) and, for real, by R4. The switch does not exist today, and the plan does not pretend it does (§8.2.2 a). |
| **D23** | **R4 keeps the refinement branch enabled**, because it is part of the published configuration — 14 of the 16 published targets refined (§5.6 b). R4's worst case is therefore **6 invocations per target and 96 for the run** (**≤ 32** GPU + **≤ 48** sandbox-CPU + **≤ 16** persistence function); the published run's own measured trace was **64** (**30** GPU + **32** sandbox-CPU + **2** persistence function). | Switching the refinement off for R4 would change the benchmark's meaning and turn a provenance migration into a benchmark re-run — the thing §10.1 forbids. The bound is therefore stated exactly and priced, not avoided: the pre-dispatch estimate of §8.2.5 refers to these counts. |
| **D24** | **The stage set becomes six keys** — `inference`, `evm_sandbox`, `refinement`, `evm_sandbox_after_refinement`, `independent_replay`, `trajectory_persistence` — all always present, in pipeline order; the producer stops **overwriting** the inference and first-verification captures under the refinement; a stage's `function_name` is bound to the capture that produced its facts (**C7**); and `modal_functions` becomes the **ordered invocation trace** (**C8**). | Under the refinement the current producer gives two stages the **wrong call's** facts (§5.6 c): the `inference` stage carries the refinement's response and identity, and the `evm_sandbox` stage the second verification's. A stage that names one function and carries another function's identity is a false provenance statement — the exact failure the §5 contract exists to prevent. The function name is bound to the capture because `StageResponseCapture` has no name field today (`evidence_integrity.py:1019-1042`) and the name is taken from the provider instead (`adapters.py:2246-2254`). |
| **D25** | **The persistence function is its own container class, and it is priced as compute at the published Function rates.** `record_trajectory_remote` declares no `cpu=` and no `memory=` (`modal_app.py:695-700`), so it runs on the platform default — a 0.125-core / 128 MiB **request**, a 16.125-core default limit, **no hard memory limit** and its own `timeout=60` — and it is billed on `max(request, actual usage)`; the persistent volume's storage is billed separately from its compute. It is therefore **neither** a sandbox-CPU call (a 2.0-core / 2048 MiB request) **nor** a free volume operation. **There is no separate "persistence" rate class**: the provider publishes CPU and memory rates by resource class, so the persistence function is priced with the **same** Function CPU and memory rates as the other Functions, plus the volume's storage rate (§8.2.5, inputs 4, 5 and 8). | Grouping the persistence call with the sandbox-CPU calls understates the sandbox calls and overstates the persistence call's rate; labelling it "volume" omits a real compute charge altogether. What the published raw billing export **cannot** resolve is the **historical** per-function share of the run's aggregate `$0.03001687` CPU line — the export is aggregated **per app session** and carries no function dimension (§5.6 g). That is an **attribution** limitation of the old evidence, not a missing price, and it blocks nothing: the published evidence publishes the app-session total, the only level the provider's export resolves (§4.4, §10.3). |
| **D26** | **A request is not a limit, and the billable lifetime is the container's, not the function's.** Every container class declares an explicit `cpu=(request, limit)` and `memory=(request, limit)` pair, an explicit `startup_timeout` and an explicit `scaledown_window`; the estimate is computed against those **limits** and against `T_billable = startup_bound + execution_bound + idle_bound`; and until the declarations are in place, the memory term of the estimate is **unbounded** and the affected steps are **not dispatchable**. | A scalar `cpu=`/`memory=` is a *request*: the provider's default CPU limit is `request + 16` and therefore moves with the request, and there is **no** default memory ceiling at all, so a container may exceed its request. And a function's `timeout` covers the **execution** phase alone, while the provider bills the container's startup and its idle retention as well. An estimate that treats requests as caps and timeouts as lifetimes is not a worst case but an understatement (§5.6 g, §8.2.5). |
| **D27** | **The container-count bound is provider-enforced, and the autoscaler is never mutated at runtime.** Every container class declares `min_containers=0`, `buffer_containers=0` and a deployed `max_containers` equal to the **union** of the authorised steps' caps for that class (48 / 32 / 16); the repository contains **no** mutating autoscaler call at all; the **per-step** effective cap is enforced by the **dispatch helper** (per-class invocation budget, per-class concurrency gate, and a ceiling assertion against the deployed value) from the step's approval record; and the effective settings are **read back** — with the **no-argument** `update_autoscaler()`, which changes nothing — before the first container and again after the step, both readings recorded. Until this is in place, the estimate's container multiplier is an arithmetic hope, and the affected steps are **not dispatchable**. | A warm pool (`min_containers`) and an idle buffer (`buffer_containers`) are billed **without carrying an invocation** — "The minimum number of containers that should be kept warm, even when the Function is inactive", "The size of the buffer to maintain while the Function is active" (Modal Docs, *Scaling out*) — and the provider publishes **no default** for either, so an unset autoscaler setting is an unknown in exactly the sense an unset memory limit is. The provider also allows the settings to be changed at runtime without a redeploy, so a silent raise would break the estimate without touching the repository — and a runtime override is a **stale** object that survives until the next deploy. That is why the repository makes **no** autoscaler call: a deployed ceiling that never changes needs no policing, and the "tightening-only" rule of the earlier draft was **internally impossible** (R3 tightens the sandbox pool to 1, and no tightening-only rule can then reach R3b's 2 or R4's 48). Note also that `max_containers` caps the **concurrency**, not the number of containers a class starts over time — a container that scales down and is replaced is a second container — so it adds a second, independent bound and cannot replace the invocation bound; it is therefore **never** used to clamp a cumulative quantity (D29) (§5.6 g, §8.2.5). |
| **D28** | **The volume is a billable object with a measured baseline, a capped increment, a bounded storage duration and a retention rule.** The estimate's volume term is `(measured baseline + capped increment) × (1 + ceil(T_store / 28 days))`, where `T_store = T_exec + T_post_exec_to_publication + T_retention`: `T_exec` is the step's **declared wall-clock budget** (bounded a second time by `ceiling / burn_rate`), `T_post_exec_to_publication` is the step's **declared post-execution deadline** — the bounded interval between the end of the compute step and the publication, during which the run's bytes stay stored — and `T_retention` is **30 days** from the publication to the verified deletion. The baseline of `aegis-model-cache` is measured by the provider's own listing before the dispatch, the increment is capped in the producer (one capped trajectory file per dispatched persistence call; the pinned model revision's bytes in the **prefetch step R2p**), the run's own files are deleted within 30 days of the publication and immediately on an abort, and the volume is re-measured afterwards. The baseline is priced for the same bounded interval, and **all run-created bytes are counted until the deletion is verified**. An unmeasurable volume, an exceeded cap, an unmeterable post-step size, an **unbounded execution duration** and an **unbounded post-execution interval** are fail-closed stops, and the affected steps are **not dispatchable**. | The provider prices volumes per GiB-month, separately from the compute of the container that writes to them, and the run writes to one (`modal_app.py:702-711`) — an unbounded storage quantity is an unbounded estimate. The earlier draft's `(baseline + increment) × 1 month` was **not** an upper bound: the bytes exist from the first write **during** the execution until the deletion **after** the publication, so the interval is a sum, not a maximum, and a run whose execution is not itself bounded has an unbounded storage duration — which is R4's state today. The two-term interval `T_exec + T_retention` was **also** not an upper bound: it skipped the interval between the end of the execution and the publication — the validation, the report, the commit, the review and the queue time — during which the bytes are still stored, so the interval is a **three**-term sum, and a step whose post-execution deadline is unbounded has an unbounded storage duration as surely as one whose execution budget is. The provider publishes no commit charge (a commit is I/O, not a fee), so the estimate does not invent one; and the free allowance belongs to the workspace's plan, not the run, so the estimate prices the full quantity and records the allowance instead of netting it out (§5.6 g, §8.2.5). |
| **D29** | **Network egress is a named term with a per-container bound, and the model download is moved into a separately approved prefetch step.** The estimate carries `Network_egress_rate × network_egress_GiB` as its **ninth** input; each container class has a **per-container payload** cap — the sandbox class at 0 under the provider-enforced blocking declaration, the GPU class at 0 **payload** in R3b/R4 (offline mode plus the verified cache manifest), the GPU class in the **prefetch step R2p** at `pinned_bytes × (1 + R_download)`, the persistence function at 0 external — plus a `protocol_allowance_GiB(c)` per container for the control-plane and data-path traffic, which is added for **every** container, including the GPU class' offline ones, because a zero payload cap is not a zero total; the **step total** sums those over the step's cold containers, whose count is bounded by the **invocation count** (`cold_containers(c) ≤ invocations(c)`) and is **not** clamped by `max_containers_deployed(c)`: that value is a **concurrency** ceiling, not a cumulative container-creation cap, and clamping by it would put the bound *below* the step's real worst case (D27); and the provider's own `Network Egress` line for the app session is the **post-run audit** of the bound, never its substitute. A class whose egress cannot be bounded makes the estimate unavailable, and the affected steps are **not dispatchable**. | The provider publishes a **separate egress rate class**, and the repository's own published billing export already carries a non-zero `Network Egress` line for the canonical app session (`$2.6E-7`) — so egress is an observed cost of this workflow, not a theoretical one. An estimate that omits a line the provider bills is not a worst case. The earlier draft priced **one** model revision for the whole GPU class, which is wrong by the source: `@modal.enter()` runs on **every** container start and downloads the model whenever the cache is cold, so the cost is **per cold container** — up to 32 of them in R4 — and a shared volume does not prevent it, because the commit follows the load. The prefetch plus the offline path is the only configuration in which the GPU steps have a bounded egress. That path makes the **payload** egress of those containers zero; it does not make their **protocol** and volume data-path traffic zero by implication, so the per-container allowance and the fail-closed rule are kept there as well. The sandbox class provably sends nothing out (the toolchain is baked into the image and the runtime runs `offline = true`), but its zero is **conditional** on the blocking declaration being provider-enforced for that exact function and path, and the proof must exist **before** the dispatch: a post-run billing report can prove an overrun, it cannot prove a bound (§5.6 g, §8.2.5). |

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
| **Q5** | What are the four monetary ceilings — the prefetch **R2p**, the CPU smoke **R3**, the GPU smoke **R3b** and the 16-target run **R4** — and the **wall-clock budget** each step declares? | §10.3, §8.2.5. R2p spends CPU time and egress *before* everything else, so its own ceiling must exist before its approval **A-R2p** is granted; R3b spends GPU credits *before* R4, so its own ceiling must exist before **A-R3b**; R4's ceiling must exist before **A-R4**; R3 is billed Modal compute too, so it has its own, smaller ceiling before **A-R3**. All four are also the input to the pre-dispatch estimate gate (D16): a step whose ceiling is unset is **not dispatchable**, so this question blocks the whole sequence, not only its paid part. **The wall-clock budgets belong to the same question**, because the budget is the step's execution bound and, through `T_exec ≤ ceiling / burn_rate`, the second bound on the **storage duration** (D28): R3 and R3b declare 20 minutes today, and **R4 declares none**, which leaves its volume term unavailable and R4 itself undispatchable until a budget is supplied. **The bound each ceiling has to cover is now fixed** (§8.2.5): R2p = 1 CPU container and one download of the pinned revision; R3 = 1 sandbox-CPU call; R3b = 1 GPU + ≤ 2 sandbox-CPU + ≤ 1 persistence-function call (refinement switched off, D22); R4 = ≤ 32 GPU + ≤ 48 sandbox-CPU + ≤ 16 persistence-function calls — the published run's own trace was 64 calls in total, split into 30 GPU + 32 sandbox-CPU + 2 persistence-function (§5.6 b). **The estimate behind each ceiling has nine named inputs** (§8.2.5). Its **rates** are all published — CPU, memory, GPU, volume storage **and network egress** — and the persistence function has **no separate rate class** (D25), the volume has **no commit fee** (D28) and egress has **no per-function rate** (D29). What the estimate still needs is the **bounds**: the explicit request/limit pairs and the explicit lifecycle bounds of all three container classes (D26), the **provider-enforced container count** of the autoscaler policy together with the dispatch helper's per-step caps (D27), the **measured volume baseline and capped increment** over the **bounded storage duration** (D28) and the **per-container egress bounds** with the prefetch's download allowance (D29). Until those exist the estimate is **unbounded**, and **no** approval — A-R2p, A-R3, A-R3b or A-R4 — can be granted, whatever the ceilings are. The **historical** per-function split of the published app-session aggregate stays unresolved (D25) and blocks nothing: it is an attribution limitation of the old evidence, and the estimate prices the future run with the published rates. | to be set by the maintainer |
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
6. The negative tests T1–T16 exist, and each was observed to fail against the pre-fix code
   (T16 excepted: it is the positive counterpart of T13 and passes only after the fix).
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
    `refinement.attempted = false`, `evm_sandbox_after_refinement.attempted = false`,
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
    stage's `function_name` (§8.2.1 e, item 7). The list is the **ordered trace** of the
    invocations — one entry per call, in dispatch order, the second `verify_exploit_remote`
    appearing **twice** (C8, D24) — and a target whose refinement fired names
    `ProductionAuditAgent.refine_solidity_exploit` in it and in the `refinement` stage's
    `function_name` (T14).
22. **"Not attempted" and "attempted and failed" are not interchangeable.** Every stage's
    `attempted` flag agrees with the absence kind its identity facts carry: a stage with
    `attempted: false` carries `STAGE_NOT_ATTEMPTED` and nothing else, and a stage with
    `attempted: true` carries none (C6, T12, §8.2.1 d).
23. **Every compute step was dispatched exactly once.** R3 made exactly **1** Modal
    invocation (a sandbox-CPU call); R3b at most **4**, all of them inside its single attempt
    (1 GPU + ≤ 2 sandbox-CPU + ≤ 1 persistence function); R4 was one authorised run of its 16
    targets and made at most **96** Modal invocations (**≤ 32** GPU + **≤ 48** sandbox-CPU +
    **≤ 16** persistence function, D23). No step was retried automatically: a step that failed
    ended there with the failure recorded, and any retry appears as a **separately named
    step** with its own approval, its own ceiling, its own pre-dispatch estimate and its own
    row in the approval record of the PR (D20, §8.2.5, §10.3).
24. **The refinement branch is executed, not described.** Every artifact of the authoritative
    run carries the **six** stage keys of §5.6 (d); `refinement.attempted` is `true` exactly
    for the targets whose first verification did not breach, and
    `evm_sandbox_after_refinement.attempted` exactly for those whose refinement returned a
    usable payload; each stage's `function_name` and its identity facts come from the **same**
    call (C7, T15); and the R3b configuration cannot dispatch `refine_solidity_exploit` at
    all (T13, D22). The mocked six-call trace (T16) covers the branch at no cost, and the
    published run's own trace — 4 calls per target, 64 in the run, split into **30 GPU + 32
    sandbox-CPU + 2 persistence function** — is the reference point the new run is compared
    against (§5.6 b).
25. **The resource classes are accounted for separately, and the persistence function is
    priced as compute at the published Function rates.** The invocation trace of the
    authoritative run is split into **GPU**, **sandbox CPU** and **persistence function**
    counts, and no stage's invocation is counted in two classes; the per-target worst case is
    **2 GPU + 3 sandbox-CPU + 1 persistence function** (§5.6 a, D21, D23). The persistence
    call is priced on its **own** container profile — no `cpu=` and no `memory=` declared, so
    the 0.125-core / 128 MiB default request, the 16.125-core default limit, no hard memory
    limit, `timeout=60`, volume attached (§5.6 g, D25) — with the **same published Function
    CPU and memory rates** as the other Functions and the volume's storage rate on top: **not**
    at the sandbox-CPU rate, **not** at zero and **not** at a rate class of its own, because
    the provider publishes none. The estimate behind every approval is computed with the
    **nine named inputs** of §8.2.5, each recorded with its source and its date; the rates
    are published, and the bounds they multiply are the explicit limits and lifecycle bounds
    of D26, the enforced container count of D27, the measured-and-capped volume quantity of
    D28 and the per-container egress bounds of D29 — and **no** approval was granted while any of
    those bounds was missing (D25, D26, D27, D28, D29, Q5, §8.2.5).
26. **The persistence stage is represented once per actual invocation.** The
    `trajectory_persistence` stage appears **once** in the stage set (§5.6 d) and its
    invocation appears **once** in the ordered `modal_functions` trace (C8, D24) — a target
    that did not dispatch it names it neither in the trace nor as a stage's `function_name`,
    and a target that did dispatch it names it exactly once (T14, §5.6 d). The trace counts
    **invocations**, not containers: a container may serve several invocations, so the
    container count is **at most** the invocation count, and the estimate uses the invocation
    count as the conservative bound (D26, D27, §5.6 g).
27. **The resource limits and the lifecycle bounds exist and are verified before any
    dispatch.** Every container class — the sandbox functions, the GPU class and the
    persistence function — declares an explicit `cpu=(request, limit)` and an explicit
    `memory=(request, limit)` pair, an explicit `startup_timeout` and an explicit
    `scaledown_window`; every declared limit is **≥** its declared request; the memory limit
    is **hard** — `memory=(request, limit)`, never a scalar — and high enough not to
    OOM-kill the real workload; and the recorded `T_billable = startup_timeout + timeout +
    scaledown_window` is the bound the estimate was computed against. The same classes
    declare the **autoscaler policy**: `min_containers=0`, `buffer_containers=0` and a
    deployed `max_containers` equal to the **union** of the authorised steps' caps for that
    class (48 / 32 / 16) — a value that is **never changed at runtime** and never raised, and
    that is a **concurrency** ceiling only: it does **not** bound the number of containers a
    class starts **over the step**, so it is never used to clamp a cumulative quantity, and
    the estimate's cumulative container bound is the **invocation count** —
    `cold_containers(c) ≤ invocations(c)` (D27, D29);
    the repository contains **no** mutating autoscaler call, and a test fails if one appears;
    the **per-step** effective cap is enforced by the **dispatch helper** (per-class
    invocation budget, per-class concurrency gate, ceiling assertion against the deployed
    value) from the step's approval record, and the effective settings are **read back** —
    with the **no-argument** `update_autoscaler()`, which changes nothing — before the first
    container and again after the step, both readings recorded. The approval record of each
    compute step names those declarations, the resulting `T_billable`, the step's
    **wall-clock budget** and **post-execution deadline**, and the rate source of each of the
    estimate's **nine** inputs.
    **No compute step was dispatched while any of them was missing** — such a step is
    recorded as "not dispatched — estimate unavailable" with its reason (D26, D27, D16,
    AC 18, §8.2.5).
28. **The volume quantity is measured, capped, bounded in time, retained and re-measured.**
    The approval record of each compute step carries the **measured baseline** of
    `aegis-model-cache` —
    the provider's own recursive listing, with its date — the **capped increment** the step
    may write (one trajectory file per dispatched persistence call, within the producer's
    hard byte cap; the pinned model revision's bytes in the **prefetch step R2p**), the
    **bounded storage duration** (`T_exec` = the step's declared wall-clock budget, itself
    bounded by `ceiling / burn_rate`; `T_post_exec_to_publication` = the step's declared
    **post-execution deadline**, the interval between the end of the compute step and the
    publication — the validation, the report, the commit, the review and the queue time —
    during which the run's bytes stay stored; `T_retention` = 30 days from the publication to
    the verified deletion), so that
    `T_store = T_exec + T_post_exec_to_publication + T_retention`, the **months** the interval
    is priced over
    (`1 + ceil(T_store / 28 days)`), the
    **cleanup event** (the run's own files deleted within 30 days of the publication, and
    immediately on an abort; and, if the post-execution deadline expires before the
    publication, the cleanup rule runs, the deletion is verified, and the step is recorded as
    **failed** with that cleanup event) and the **post-step re-measurement** of the
    volume. The estimate's volume term is `(baseline + increment) × months`, with its rate
    source and date recorded; the baseline is priced for the same bounded interval; **all
    run-created bytes are counted until the deletion is verified**, and an unverified
    deletion carries the increment into the next step's baseline, where it is priced again;
    the provider's free allowance is recorded but
    **not** netted out, and no commit fee appears anywhere in the estimate. A step whose
    volume could not be measured, whose **duration was not bounded** — neither the execution
    nor the post-execution interval — or whose measured size
    exceeded the bound, is recorded as
    "not dispatched — estimate unavailable" or as an overrun with the cleanup run — never as
    a passing step (D28, §8.2.5).
29. **Every container class's egress is bounded per container, and the provider's own line is
    the post-run audit.** The approval record of each compute step names the **per-container**
    egress bound and how it was established — the sandbox class at 0 under the
    provider-enforced blocking declaration, proved **before** the dispatch (the declaration
    on that exact function, the source-level proof that the runtime path needs no external
    network, and the dispatch helper's assertion), the GPU class at 0 **payload** in R3b/R4 under the
    offline mode plus the verified cache manifest, the GPU class in the **prefetch step R2p**
    at `pinned_bytes × (1 + R_download)`, the persistence function at 0 external — those four are **payload** caps — together
    with the `protocol_allowance_GiB(c)` per container, which is added for **every** container
    of **every** class, including the GPU class' offline containers in R3b/R4, because a zero
    payload cap is not a zero total, and
    the rate source and the date of the egress input. The **step total** is the per-container
    payload cap plus the per-container protocol allowance, each summed over the step's cold
    containers, whose count is bounded by the **invocation count** —
    `cold_containers(c) ≤ invocations(c)` — and is **not** clamped by
    `max_containers_deployed(c)`: that value is a **concurrency** ceiling, not a cumulative
    container-creation cap, and a clamp by it would sit **below** the step's true worst case
    (D27, D29). After the step, the app session's
    `Network Egress` line is read from the provider's own billing report and is **not** above
    the estimated bound; a larger line is an overrun that aborts the step. That report is an
    **audit** of the bound and never its substitute. A class whose
    egress could not be bounded makes the estimate unavailable, and that step was recorded
    as "not dispatched — estimate unavailable" with its reason (D29, §8.2.5).

---

## 12. What was deliberately not done

* No code implementation. The schema of §5, the call-path changes of §6.5 and the tests of
  §6.6 are **specified**, not written.
* No published evidence artifact was regenerated, renamed, rewritten or re-pinned.
* No validator, schema, test, manifest, billing table or historical report was changed.
* No live Modal invocation, no deployment, no redeployment, no H100/T4 allocation, no
  Foundry remote run, no paid computation. No Modal credits were spent.
* **No live call was made to observe the refinement branch.** Its behaviour was established
  by reading the producer source at the baseline commit and at the published run's commit
  `70f5d22`, and by measuring the published artifacts' own bytes (`candidates_generated`,
  `tool_metadata.modal_functions`, §5.6 b) — not by a live run. The counts of §8.2.5 are
  derived from that source, and the 64-call figure is a measurement of the published run,
  not an estimate. Its **resource-class split** — 30 GPU + 32 sandbox-CPU + 2 persistence
  function — is derived from the same source and the same artifact bytes, split by the
  function each call went to (§5.6 a, b, g).
* **No live call was made to measure the persistence function's own cost.** Its resource
  profile was established from `modal_app.py:695-700` and from the provider's published
  documentation (§5.6 g), and the fact that the repository's billing evidence **cannot**
  resolve its **historical** per-function share — the export is aggregated per app session
  and carries no function dimension — was established by reading the published raw export's
  own 25 line items. That share stays **unresolved**; it is an attribution limitation of the
  old evidence, not a missing price, and it blocks nothing (D25). The **blocking** gap is a
  different one, and the plan names it: the estimate's **bounds** — the explicit
  request/limit pairs and the explicit lifecycle bounds — do not exist in the producer yet,
  so the estimate is **unbounded** and R2p, R3, R3b and R4 stay **not dispatchable** (D26, Q5).
* No compute step was authorised: the approvals **A-R2p**, **A-R3**, **A-R3b** and **A-R4** of
  §8.2.5 are
  specified here, and none of them was granted. The caps and the ceilings of §8.2.5 are a
  specification, not a budget that was spent. No step was dispatched, no step was retried and
  no retry step was created (D20).
* No cost estimate was computed for any step and no provider rate was read into the
  repository: the pre-dispatch estimate gate (D16, §8.2.5) is specified, not exercised. The
  numeric ceilings of R2p, R3, R3b and R4 remain unresolved (**Q5**), so none of the four steps
  is dispatchable. Independently of the ceilings, the estimate's **bounds** are missing as
  well: no container class declares a hard memory limit, no class declares an explicit
  startup or idle bound, and the default CPU limit moves with the request — so the memory
  term is **unbounded** and no step is dispatchable even if its ceiling were set today
  (D26, §5.6 g). The same holds for the container count (no autoscaler setting is declared),
  the volume quantity (no baseline was measured, no increment capped and no duration bounded —
  **R4 declares no wall-clock budget at all**) and the egress quantity (no class's egress
  was bounded, and the GPU model's download is a **per-cold-container** cost that the plan
  moves into the prefetch step R2p). The **rates** the estimate multiplies were checked
  against the provider's
  published documentation, but no rate was read, copied or hardcoded anywhere.
* **No autoscaler setting was changed, and no deployed Function was inspected.** No
  `min_containers`, `buffer_containers` or `max_containers` was set, no autoscaler update was
  called, and no deployment was made or redeployed; the effective-settings read-back that
  D27 requires is specified, not performed. The provider facts it rests on — the four
  autoscaler settings, their runtime mutability and the platform's concurrency limits — come
  from the provider's published documentation, quoted with their URL in §5.6 g. The **SDK
  facts** of the read-back come from the **pinned local SDK 1.5.5** itself: it exposes
  `Function.update_autoscaler(min_containers=…, max_containers=…, buffer_containers=…,
  scaledown_window=…)`, whose own documentation states that unspecified parameters retain
  their current value — which is what makes the **no-argument** call a non-mutating read-back
  — and it has **no** `Function.autoscaler` namespace, so the read-back path D27 names is the
  one this SDK actually offers.
* **No volume was measured, written or deleted.** The volume `aegis-model-cache` was not
  listed, no byte size was read, no trajectory file was created or removed, and the cleanup
  rule of D28 does not exist yet in the producer. The volume's baseline is therefore
  **unknown to this plan** — which is exactly why the estimate is unavailable and the steps
  are not dispatchable.
* **No egress was measured.** No container was dispatched and no traffic was observed, so no
  egress quantity was measured; the bounds of D29 rest on the source (the toolchain is baked
  into the image, the runtime runs `offline = true`, the GPU class' model download happens in
  `@modal.enter()` on **every** container start and is therefore a **per-cold-container**
  cost) and on the provider's published rate class. The one egress figure in this plan is
  the repository's own published evidence — the `Network Egress $2.6E-7` line of the
  canonical app session in `benchmarks/evidence/modal_billing_report_raw.json`.
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
