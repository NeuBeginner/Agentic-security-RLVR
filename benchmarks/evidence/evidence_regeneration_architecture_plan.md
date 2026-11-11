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
| **F1** | The pseudo-URI inventory is **165**, not 99. The 99 of the task counts only two of the four files that carry the URIs (§2). | The inventory in §2 enumerates all 165 occurrences, by file, JSON path and value. |
| **F2** | The current validator **already rejects** the published pseudo-URIs — but for a *different, earlier* reason than the URI. Iterations 14–18 fail on `missing 'function_call_id'` and `missing 'image_digest'`, i.e. the URI check is never reached (§4.2). | The regeneration cannot be "clean up the URI"; it must **replace the whole provenance schema** of the artifacts, because the schema the URI lives in is itself rejected. |
| **F3** | The upstream bytes are **not** a drop-in replacement. Upstream's rewritten artifacts still fail the iteration-line validators, and they introduce a *new* defect: a synthetic `container_id` of the exact shape the validator forbids (§3.2). | The upstream bytes cannot be taken as-is. §5 specifies a third contract: iteration-line schema **+** upstream's `NOT_AVAILABLE` honesty **+** upstream's field rename, with the upstream defects fixed. |
| **F4** | `has_synthetic_modal_uri` is **not enforced** on the authoritative paths. In Iterations 14–16 it is recorded as a diagnostic field (`synthetic_uri_present`) next to a billing check whose verdict it does not influence; Iterations 17–23 and the closure validator do not call it at all (§4.3). | §6 specifies the exact call-path changes needed to make the detector authoritative, plus the negative tests that prove it. |
| **F5** | The SHA-256 pins do **not** bind the 16 target artifacts. The published evidence pins the *stdout/stderr* files and the harness validation, but not the 16 target JSONs themselves (§7.1). | The blast radius of a regeneration is narrower than the task assumes, but it is **not zero**: the harness validation file is pinned 17× by the join table, and the target artifacts are bound by *validator verdicts* rather than by digests. |

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

`benchmarks/artifacts/` is listed in `.gitignore` (line 14), but 37 files of the run
directory `run_1794209615_70f5d22` are **tracked** and therefore published. The tracked set
is the authoritative definition of "published" for this plan:

```
$ git ls-files benchmarks/artifacts/run_1794209615_70f5d22/ | wc -l
37
```

They are: 16 × `<TARGET>-01.json`, the per-target stdout/stderr/replay files, plus
`reproducibility_manifest.json`, `summary.json` and (at the tree root) `latest_summary.json`.

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

A deterministic script walks every tracked JSON file, parses it, and records every string
value that starts with `modal-app://`, together with its full JSON path. The script is
reproducible and its output is quoted verbatim below. Nothing was modified; the script only
reads.

```python
# inventory of the fabricated modal-app:// pseudo-URIs
import json, subprocess
from pathlib import Path

ROOT = Path(r"<repo>")
RUN = ROOT / "benchmarks" / "artifacts" / "run_1794209615_70f5d22"

def walk(node, path, out):
    if isinstance(node, dict):
        for k, v in node.items():
            walk(v, path + [str(k)], out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, path + [f"[{i}]"], out)
    elif isinstance(node, str) and node.startswith("modal-app://"):
        out.append(("/".join(path), node))

def scan(p):
    out = []
    walk(json.loads(p.read_text(encoding="utf-8")), [], out)
    return out

total = 0
for p in sorted(RUN.rglob("*.json")):
    hits = scan(p)
    if hits:
        rel = p.relative_to(ROOT).as_posix()
        print(f"### {rel}  ({len(hits)})")
        for jp, val in hits:
            print(f"    {jp}\t{val}")
        print()
        total += len(hits)
print("RUN DIR TOTAL:", total)
```

### 2.2 The count: 165, not 99

```
=== per-category totals (run_1794209615_70f5d22) ===
target artifacts (baseline_5): 66 occurrences in 16 files
reproducibility_manifest.json: 33 occurrences in 1 file
run summary.json: 33 occurrences in 1 file

ARTIFACTS_TREE_TOTAL (incl. latest_summary.json): 165
```

| File class | Files | Occurrences | Tracked? |
|---|---|---|---|
| 16 target artifacts (`baseline_5/<TARGET>-01.json`) | 16 | **66** | yes |
| `reproducibility_manifest.json` | 1 | **33** | yes |
| `summary.json` (run dir) | 1 | **33** | yes |
| `latest_summary.json` (tree root) | 1 | **33** | yes (byte-identical to `summary.json`) |
| **Total** | **19** | **165** | all tracked |

The task's figure of 99 = 66 (targets) + 33 (manifest) counts two of the four files. It
misses `summary.json` and `latest_summary.json`, which carry the same 33 occurrences. The
miss is material for the plan: `summary.json` and `latest_summary.json` are the run-level
views, and `latest_summary.json` is byte-identical to `summary.json`
(`sha256 = 3ff3993e0d6f7b50a070daff1504756435541057de83febef6e86b5136d6ba47`), so they are
one artifact with two copies — but both copies must be regenerated, or the tree contradicts
itself.

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

Three distinct path shapes carry all 165 occurrences:

```
modal_invocation_provenance/stages/<stage>/durable_log_ref
tool_metadata/modal_invocation_provenance/stages/<stage>/durable_log_ref
reproducibility_manifest.adapters.baseline_5.per_target_provenance.<TARGET>\
    .modal_invocation_provenance/stages/<stage>/durable_log_ref
```

In the manifest and the summaries the same per-target block appears once per target under
`adapters.baseline_5.per_target_provenance.<TARGET>`; in `summary.json` and
`latest_summary.json` it is additionally nested under `reproducibility_manifest_summary`.

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
`cost_usd: null` and a machine-readable reason, each citing
`app_id_evidence_ref → modal_control_harness_validation.json`
(`sha256 = 7a56eadb…`). The billing join therefore **does not need to be regenerated** for a
provenance-schema migration — only its `app_id_evidence_ref` digest changes if the harness
validation file changes (§7).

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

The rename upstream proposes is **semantically better** and this plan adopts it, with one
caveat: `app_session_id` is *not* a session id. It is the **provider-issued application id**
of the running app — a value that identifies the app, not the session. Upstream's own value
is the same literal `ap-EDUitOwWeMrIdYbTh4kB63` in every row, which confirms it is the app id.

Recommendation: name the field `app_session_id` **only if** the maintainer accepts that the
name is slightly imprecise; otherwise `app_id` is the more accurate name and the rename
becomes unnecessary. This is **decision D3** (§11).

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
                    │                            │
                    └──x1──> modal_billing_report_raw.json
                                 
modal_control_harness_validation.json ──> 16× <TARGET>_stdout.txt
                                   ──>    2× <TARGET>_replay_stdout.txt
                                   ──>    1× SIG-01_stderr.txt
                                   ──>    1× REENT-01_replay_stdout.txt
                                   ──>    16× benchmarks/targets/solidity/*.sol

iteration16/17/18_validation_evidence.json ──x1 each──> their 4 rehearsal stage-evidence files
iteration19_validation_evidence.json ──x2──> CPU-SMOKE-01_stage_evidence_cpu_smoke.json
iteration20_validation_evidence.json ──x2──> ITER20-01_stage_evidence_evm_sandbox.json
iteration21/22/23_validation_evidence.json ──x2──> ITER21-01_stage_evidence_evm_sandbox.json
```

### 7.3 The blast radius of a regeneration

**Not pinned by digest, but bound by verdict — the 16 target artifacts.** No evidence file
contains the SHA-256 of `<TARGET>-01.json`. Their binding is *semantic*: the Iteration 14–18
validators read them from disk and produce a verdict that the published evidence records.
Regenerating them changes those verdicts' inputs, and therefore the published
`iteration14..18_validation_evidence.json` files must be regenerated to match.

**Directly pinned — `modal_control_harness_validation.json`.** It pins the 16 stdout files
and the 16 Solidity sources. If the regeneration re-runs the benchmark, the stdout bytes
change, so the harness validation file changes, so:

- its own sha changes from `7a56eadb…` to a new value;
- the join table's 17 `app_id_evidence_ref` entries and its 1 `source_raw_export` entry
  must be updated to the new digest;
- the join table's own sha changes from `8f62a23d…`;
- the closure validator's P6.15 re-checks the *stage evidence* digest, and the Iteration
  19–23 validators re-check their own pins.

**Unaffected.** `modal_billing_report_raw.json` is the raw billing export — it is the
*input*, not the product of a run, so it does not change unless a new billing period is
exported. The Solidity sources do not change. The Iteration 16–18 rehearsal artifacts are
produced by a separate rehearsal path and stay valid.

### 7.4 Impact matrix

| # | File | Digest pinned by | Changes? | Action |
|---|---|---|---|---|
| 1 | 16 × `baseline_5/<TARGET>-01.json` | — (verdict-bound only) | **yes** | regenerate |
| 2 | `reproducibility_manifest.json` | — (verdict-bound) | **yes** | regenerate |
| 3 | `summary.json` | — (verdict-bound) | **yes** | regenerate |
| 4 | `latest_summary.json` | — (verdict-bound) | **yes** | regenerate (must stay byte-identical to `summary.json`) |
| 5 | 16 × `<TARGET>_stdout.txt` | `modal_control_harness_validation.json` ×1 each | **yes** | regenerate with the run |
| 6 | `<TARGET>_stderr.txt`, `_replay_stdout.txt`, `_replay_stderr.txt` | harness ×1 (SIG-01_stderr, REENT-01_replay_stdout) | possibly | regenerate with the run |
| 7 | `modal_control_harness_validation.json` | join table ×17 | **yes** | regenerate, then re-pin |
| 8 | `modal_billing_join_table.json` | — (validated against the raw export) | **yes** (digests only) | regenerate the digests, keep schema 3.0.0 |
| 9 | `modal_billing_report_raw.json` | join table ×1 | no | keep as-is unless the billing window changes |
| 10 | `iteration14..18_validation_evidence.json` | — (published verdicts) | **yes** | regenerate; must stay `FAILED (0/16)` |
| 11 | `iteration19..23_validation_evidence.json` | rehearsal/capture stage files | **yes** (if the capture is redone) | regenerate |
| 12 | `consolidated_closure_validation_evidence.json` | — | **yes** | regenerate; must stay 21/21 PASSED |
| 13 | `benchmarks/targets/solidity/*.sol` | harness ×1 each | no | keep |
| 14 | `iteration16..18_producer_rehearsal/*` | iteration16..18 evidence | no | keep |

---

## 8. The atomic regeneration sequence

### 8.1 Preconditions (all must hold before step 1)

1. Explicit maintainer authorisation for a regeneration iteration (this plan is a proposal).
2. A clean LF checkout: `git -c core.autocrlf=false worktree add --detach <path> <branch>`.
3. `foundry`/`forge` on `PATH` in the worker image; the local machine does not need it.
4. Modal credentials for the target workspace; the app name `aegis-rlvr-security` is the
   one recorded in the published artifacts.
5. A cost ceiling agreed in advance (§10.3).

### 8.2 The sequence

Each step is atomic: it either completes and is committed, or the tree is rolled back to
the last committed step (§8.4).

| Step | Action | Produces | Gate before proceeding |
|---|---|---|---|
| **R0** | Branch `iter-24/evidence-regeneration` from the authorised base. | — | clean tree, base SHA recorded |
| **R1** | Implement the §5 schema in the producer (`adapters.py`, `modal_app.py`, `benchmark_runner.py`) and the §6.5 validator changes. | code only | unit tests green; **no** published file touched |
| **R2** | Add the §6.6 negative tests T1–T9. | tests | each test fails on the pre-fix code and passes on the post-fix code (proven by running both revisions) |
| **R3** | Dry-run the capture on **one** target (`AC-01`), CPU only, no inference stage. | one throwaway artifact outside `benchmarks/evidence/` | the produced artifact passes `validate_modal_invocation_provenance` **and** `validate_remote_evm_toolchain_provenance`; every fact has a source; no `modal-app://`; no synthetic container id |
| **R4** | Authorised live run: 16 targets, the same provider configuration as the published run (`modal_h100`, `qtum/Qwen3-Coder-30B-A3B-Audit`, `--hypotheses=3`). | a new run directory `run_<epoch>_<sha7>/` | every stage's provenance is observed-or-explicitly-`NOT_AVAILABLE`; the run completes |
| **R5** | Verify the new run **before** it becomes published: run the §5 validators over the new run dir; assert `has_synthetic_modal_uri` is false for every file; assert no `SYNTHETIC_CONTAINER_ID_RE` match anywhere. | a verification transcript | all assertions hold |
| **R6** | Replace the published run tree: the 16 target artifacts, the manifest, `summary.json`, `latest_summary.json`. | new published bytes | `git diff --stat` shows only the expected files; `latest_summary.json` is byte-identical to `summary.json` |
| **R7** | Regenerate `modal_control_harness_validation.json` (re-pin the stdout files and the Solidity sources). | new digest | the file validates against the new run dir |
| **R8** | Regenerate `modal_billing_join_table.json` (schema 3.0.0 preserved; only the `app_id_evidence_ref` digests change). | new digest | `python -m benchmarks.regenerate_billing_join_table --check` → PASSED; `validate_billing_attribution` → PASSED |
| **R9** | Regenerate `iteration14..18_validation_evidence.json`. | new verdicts | **must remain `FAILED (0/16 targets)`** (§9.4) |
| **R10** | Regenerate `iteration19..23_validation_evidence.json` and `consolidated_closure_validation_evidence.json`. | new verdicts | iterations 19–23 `PASSED`; closure `21/21 PASSED` |
| **R11** | Full test suite; then the complete validator sweep. | transcript | `pytest -q` green; every validator exits 0 with the expected verdict string |
| **R12** | Open a Draft PR with the full before/after inventory and the verifier transcript. | reviewable diff | maintainer approval |

### 8.3 Ordering rationale

The order is a strict dependency chain:

```
R4 (run) ──> R5 (verify new bytes) ──> R6 (publish run tree)
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              v                          v                          v
        R7 (harness)              R9 (iter 14-18)              R3/R4 artifacts
              │                          │
              v                          │
        R8 (join table)                  │
              │                          │
              └──────────┬───────────────┘
                         v
              R10 (iter 19-23 + closure) ──> R11 (full suite) ──> R12 (PR)
```

R5 sits **before** R6 on purpose: the new bytes are verified while they are still outside
the published tree, so a bad run never becomes published evidence.

### 8.4 Rollback

Every step is a separate commit on the regeneration branch. Rollback is therefore:

```bash
git reset --hard <last-good-step-sha>
```

plus, if R4 produced a live run that must be discarded, the deletion of the run directory
and the re-export of the billing window if a new one was opened. Because the published
tree is only touched from R6 onwards, a rollback to R5's commit restores the published
evidence byte-for-byte. The published evidence before R6 is recoverable from the base
commit `a8a8857` — every published file is tracked, so `git show a8a8857:<path>` always
yields the original bytes.

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

### 9.2 The subtlety that decides the outcome

A regeneration *does* produce a genuinely new authorised empirical run — so the condition's
exception applies and Iterations 14–18 *may* turn green. **But that is not the point, and
it must not be the outcome by accident.**

The reason Iterations 14–18 fail today is that the published artifacts predate the fixes.
After R4, the artifacts carry the new schema, so the same validators would now pass. That
is the *correct* result of an authorised regeneration — but it must be a **consequence of the
new evidence**, not a rewriting of the old verdict.

The rule this plan proposes:

> Iterations 14–18 keep their published `FAILED (0/16)` verdicts **until** a new run exists
> that passes the validators. The regenerated `iteration14..18_validation_evidence.json`
> files are produced by running the validators against the **new** run directory. If the new
> run passes, the regenerated reports say `PASSED` and the diff shows the transition — with
> the old failed reports preserved in the commit history and in the change-impact matrix.
> If the new run does not pass, the regenerated reports say `FAILED` and nothing changes.

Either way, **no report is hand-edited**. Every published verdict is the output of the
validator against bytes on disk. That is what makes "never rewrite history" enforceable
rather than aspirational.

### 9.3 The producer-source immutability check (P6.14)

The closure validator asserts that the producer source is byte-wise unchanged between the
capture commit `40c063093c8d773d20f828fb290c68b5790a7cc5` and the reported commit:

```python
capture_sha = "40c063093c8d773d20f828fb290c68b5790a7cc5"
elif not _is_ancestor(capture_sha, code_sha): ...
diff = ...  # producer source diff
if producer_changed:
    producer_errors.append("the producer source changed between the commit the capture was made from ...")
```

**Consequence for the plan:** R1 changes the producer, and R4's capture is made from the
**changed** producer. So the capture SHA of the new iteration 24 evidence is the R1 commit,
not `40c06309…`. The closure validator's `capture_sha` must be updated to the new capture
commit — and that constant is itself part of the validator, so it is a coordinated change
(R1 + R10), not an oversight. This is also why R1 and R4 must not be separated by a
producer change.

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

`HISTORICAL_EVIDENCE` therefore encodes, per iteration, the expected verdict string and the
expected `code_sha` binding. After a regeneration this table must be updated **together
with** the regenerated reports — otherwise P6.13 fails with "does not report 'FAILED
(0/16 targets)'" or "does not report 'PASSED'". The same applies to the bound SHAs
(`43436b02…` etc.), which change when the reports are regenerated.

**This is the single most dangerous coupling in the whole plan:** P6.13 asserts the *verdict
strings*, so a regeneration that turns Iterations 14–18 green must update `HISTORICAL_EVIDENCE`
in the same commit as the regenerated reports. It is listed as decision **D2** (§11) because
it is a semantic decision (does the maintainer accept the transition from FAILED to PASSED?)
and not a mechanical one.

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
2. **Single-target smoke (minimal cost):** one target, `--provider=modal_cpu` if the
   inference stage permits, to prove the provenance plumbing end-to-end (R3). Assert the
   §5 contract before any 16-target run.
3. **Full run (cost):** the 16 targets, `modal_h100`, `--hypotheses=3`.
4. **Client-side correlation:** for every stage, resolve the provider-issued
   `container_id` from the `function_call_id` the worker observed, using
   `call_graph_inputs` → `containers_of_app` → `task_app_id`, with the last one as an
   independent cross-check. If the provider does not answer, the field is recorded
   `NOT_AVAILABLE` with the provider's own reason — **never** a synthetic id (§6.6 T5).
5. **Billing export:** export the raw billing line items for the run's window
   (`modal app billing` / the workspace's billing export) into
   `modal_billing_report_raw.json`.
6. **Join table:** regenerate schema 3.0.0 from the raw export; target-level costs stay
   `null` unless an exact, unique provider join exists.

### 10.3 Cost controls

| Control | Value |
|---|---|
| Pre-agreed ceiling | to be set by the maintainer (decision **D4**) |
| Target cost attribution | `null` + `UNATTRIBUTED_NO_INVOCATION_LEVEL_JOIN` unless a proven join exists — the existing policy already prevents a target cost from being invented |
| Aggregate allocation | `FORBIDDEN` (`attribution_policy.aggregate_bucket_allocation`) — no aggregate bucket may be spread over targets |
| App-session granularity | the app-session total is the only cost that may be published |
| Pre-flight | the smoke run in step 2 happens **before** the 16-target run and must be reviewed |
| GPU | `H100` only where the original run used it; `CPU` for the EVM-sandbox and replay stages |

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

| # | Decision | Rationale |
|---|---|---|
| **D1** | The regeneration is a **schema migration**, not a value cleanup. | The published schema is rejected as a whole (F2); a URI-only edit would leave `app_id`/`function_call_id`/`container_id` and the flat EVM facts still invalid. |
| **D2** | The upstream bytes are **not** adopted; they are used as a field-level reference only, and their three defects (§3.2) are fixed. | Upstream's bytes fail the iteration-line validators and add a synthetic container id (F3). |
| **D3** | The iteration-line `observed()` / `not_available()` envelope is the target contract; upstream's flat `"NOT_AVAILABLE"` strings are **not**. | The envelope carries a reason, an absence kind, an observation side and a digest-checked evidence reference — the Iteration 15/16/20 rules. Flat strings satisfy none of them. |
| **D4** | The producer's `capture_modal_runtime_identity` is reused as-is for the worker side; the client side uses `ModalProvider` (already implemented, currently unwired). | Both are already in the tree and already honest. The plan wires them; it does not reinvent them. |
| **D5** | `image_digest` is `NOT_AVAILABLE` with a reason unless the provider issues the image id client-side. | The container sandbox exposes no OCI manifest digest; a digest cannot be derived from a tag. |
| **D6** | The `legacy_key` inline check stays; `has_synthetic_modal_uri` is additionally promoted to a **verdict** on the artifact, manifest, summary and join-table paths. | §6.5 C1–C3; the detector exists but is not enforced (F4). |
| **D7** | The published verdicts are never hand-edited; every regenerated report is a validator run. | §9.2. |

### 11.2 Unresolved questions for the maintainer

| # | Question | Why it blocks | Options |
|---|---|---|---|
| **Q1** | Is the `app_session_id` rename wanted? | Changes the published field name in 16 artifacts + manifest + summaries | (a) rename to `app_session_id`; (b) keep `modal_app_id`; (c) rename to `app_id` (more precise — the value is the app id, not a session) |
| **Q2** | May Iterations 14–18 transition from `FAILED (0/16)` to `PASSED` after an authorised regeneration? | Determines whether `HISTORICAL_EVIDENCE` in the closure validator is updated, and it changes the meaning of the published history (§9.4) | (a) yes, if the new run passes — the transition is documented in the change-impact matrix; (b) no — keep the failed reports and add the new run as a separate iteration (24) |
| **Q3** | Is `modal_app_id` → `app_session_id` + the upstream's *other* field removals (`stages.*.resource_interval`, `stages.*.billing_line_item`) in scope? | The upstream removed those fields; the iteration line's validator expects per-stage `app_id`/`function_call_id`/`container_id` and the join table carries the billing detail | (a) keep the iteration-line field set; (b) adopt upstream's set and relax the validator |
| **Q4** | Is `remote_os` allowed to keep its coincident legacy value? | `EVM_FACTS_WITH_COINCIDENT_LEGACY_VALUE` already permits it **when the source proves it**; the plan makes the source real. If the worker's real `/etc/os-release` says something else, the value changes and the pin changes | (a) accept whatever the worker observes; (b) require an exact value match as a gate |
| **Q5** | What is the cost ceiling for the authorised run? | §10.3 | to be set by the maintainer |
| **Q6** | Should the regenerated run **replace** `run_1794209615_70f5d22` or live beside it as a new directory? | A new directory keeps the old bytes reachable (cleaner rollback, but the old pseudo-URIs stay in the tree) | (a) replace in place; (b) add `run_<new>` and keep the old — but then the old pseudo-URIs must be marked as superseded, and the validators must not read them |
| **Q7** | Should `latest_summary.json` remain a byte-identical copy of `summary.json`? | Today it is; the plan keeps that invariant | (a) keep the invariant (recommended — it is checkable); (b) make `latest_summary.json` a pointer file |

### 11.3 Acceptance criteria for the implementation (future iteration)

The regeneration is acceptable only when **all** of the following hold:

1. `has_synthetic_modal_uri` is `False` for every published JSON file — verified by the
   §2 script, output committed with the diff.
2. No string in any published artifact matches `SYNTHETIC_CONTAINER_ID_RE`.
3. Every published artifact passes `validate_modal_invocation_provenance` **and**
   `validate_remote_evm_toolchain_provenance`.
4. Every remote-EVM fact is either an `observed` envelope with a source matching
   `EVM_FACT_REQUIRED_SOURCE_TOKENS`, or a `not_available` envelope with a reason, an
   absence kind and — where the provider should have answered — a digest-valid
   `evidence_ref`.
5. No value in the new artifacts was copied from the old artifacts or from upstream's
   bytes. The run directory is new; its bytes come from a new run.
6. The negative tests T1–T9 exist, and each was observed to fail against the pre-fix code.
7. `python -m benchmarks.regenerate_billing_join_table --check` → PASSED, and the join
   table is still schema 3.0.0 with `aggregate_bucket_allocation: "FORBIDDEN"`.
8. Every validator exits 0 and reports its expected verdict:
   iterations 14–18 → `FAILED (0/16)` or `PASSED` per **Q2**;
   iterations 19–23 → `PASSED`; closure → `21/21 PASSED`.
9. `pytest -q` is green, with no test weakened, relaxed or skipped. The seven live-provider
   skips (Foundry not on `PATH`, Slither not installed) remain skips and are run only by
   the `foundry-integration` CI job on the Linux runner.
10. `git diff --stat` shows only the files listed in §7.4, and the diff contains no
    hand-edited verdict.

---

## 12. What was deliberately not done

* No code implementation. The schema of §5, the call-path changes of §6.5 and the tests of
  §6.6 are **specified**, not written.
* No published evidence artifact was regenerated, renamed, rewritten or re-pinned.
* No validator, schema, test, manifest, billing table or historical report was changed.
* No live Modal invocation, no deployment, no redeployment, no H100/T4 allocation, no
  Foundry remote run, no paid computation. No Modal credits were spent.
* No published digest was re-computed into a record.
* The historical FAILED (0/16) results of Iterations 14–18 were not rewritten.
* PR #12 and PR #13 were not merged, re-based, closed or modified; their base branches and
  `main` were not touched.
* The only file added by this iteration is this document.
