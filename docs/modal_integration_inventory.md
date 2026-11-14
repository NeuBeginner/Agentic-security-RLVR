# Modal integration inventory — CPU audit service

**Scope:** the read-only inventory of the Modal infrastructure that this workstream
depends on, collected on 2026-11-14 **before** any resource of this workstream was
created, plus the re-measurement of the same facts after the deployment.

| | |
|---|---|
| Repository | `NeuBeginner/Agentic-security-RLVR` |
| Workspace | `neubeginner` (environment `main`) |
| Modal client | 1.5.5 |
| Python SDK | `modal` 1.5.5 · Python 3.10.11 · Windows 10.0.22631 x64 |
| Machine-readable evidence | `benchmarks/evidence/cpu_audit/` |
| Inventory report | this document |

Every number below is the output of a command or of the SDK, not an assumption. The
commands are listed next to the facts they produced.

---

## 0. The profile trap — read this before any SDK call

The Modal SDK resolves the workspace from the **active profile** at the moment of the
call. The active profile of this machine is `iozornick27`, which is **not** the
workspace of this project.

The proof that this matters: both workspaces contain a volume named
`aegis-model-cache`.

| Workspace | Volume `aegis-model-cache` | Created |
|---|---|---|
| `neubeginner` (this project) | the model cache of the audit model — `checkpoints/`, `huggingface/`, `trajectories/` | 2026-10-31 09:42 CET by `neubeginner` |
| `iozornick27` (the default profile) | a different cache — only `huggingface/` | 2026-11-09 07:48 CET by `iozornick27` |

An SDK call that does not pin the profile silently reads the **wrong** volume. Every
SDK call of this workstream therefore sets `MODAL_PROFILE=neubeginner` explicitly, and
every CLI call passes `--profile neubeginner`.

```powershell
$env:MODAL_PROFILE = 'neubeginner'
```

The CLI and the SDK agreed on every fact of this document once the profile was pinned
on both sides.

---

## 1. CLI, SDK and authorisation — `VERIFIED`

```powershell
modal --version          # modal client version: 1.5.5
python -c "import modal; print(modal.__version__)"   # 1.5.5
modal profile list       # 54 profiles; the workspace of this project is `neubeginner`
```

Authorisation works for the workspace of the project: read operations
(`modal app list`, `modal volume list`, `modal volume ls`, `modal billing summary`)
and a deployment (`modal deploy`) were executed successfully against
`--profile neubeginner`.

**SDK compatibility with the project — `VERIFIED` for this workstream, with one
documented caveat of the repository at large:**

* The public client of SDK 1.5.5 is **synchronous** (`Client = synchronize_api(_Client)`,
  `modal/client.py:532`). `await Client.from_env()` raises
  `TypeError: object Client can't be used in 'await' expression`.
* The repository hit exactly this defect in its own read-back reader and fixed it on
  the same day — see `docs/r1_sdk_compat_report_20261114.md` and
  `benchmarks/evidence/r1_sdk_compat_20261114/`. The fix uses the asynchronous client
  on the SDK's own synchroniser loop.
* **The CPU service of this workstream does not use the client API at all.** It uses
  only the public object API (`Volume.iterdir`, `Volume.read_file`, `Function.remote`),
  so the synchronous/asynchronous distinction cannot affect it. The driver uses
  `App.lookup()` and `Function.from_name(...).remote.aio(...)`, both of which are
  public and stable in 1.5.5.

---

## 2. Applications — `VERIFIED`

```powershell
modal app list --profile neubeginner
modal app history aegis-rlvr-security --profile neubeginner
```

Before this workstream, the workspace held **no application at all**: the listing was
empty, and the history of the production application reported

```
No App with name 'aegis-rlvr-security' found in the 'main' environment.
```

The GPU production application of the repository (`core/config.py:8`,
`APP_NAME = "aegis-rlvr-security"`) therefore does **not** exist in the workspace: it
was deployed on 2026-10-30/31 and is not listed any more. Nothing of the GPU path
could be affected by this workstream, and nothing of this workstream depends on it.

---

## 3. Volumes — `VERIFIED`

```powershell
modal volume list --profile neubeginner
modal volume ls aegis-model-cache --profile neubeginner
```

| Volume | Created | Created by | Role |
|---|---|---|---|
| `aegis-model-cache` | 2026-10-31 09:42 CET | `neubeginner` | the existing model cache — **read-only** for this workstream |
| `aegis-cpu-audit-results` | 2026-11-14 17:20 CET | `neubeginner` | the artifacts of the CPU service — **created by this workstream** |

The second volume is a **new** resource. It was created only after the inventory of
this document was complete, it holds nothing but the results of the CPU service
(`runs/<run_id>/result.json`), and it is deliberately separate from the model cache so
that no write of this workstream can ever touch the existing data.

### 3.1 The measured content of the model cache — `VERIFIED`

Measured with the SDK (`MODAL_PROFILE=neubeginner`), one recursive listing from the
root, `Volume.iterdir("/", recursive=True)`:

| Measure | Value |
|---|---|
| Entries | **247** = 156 files + 42 directories + 49 other entries (hub symlinks) |
| **Total file bytes** | **64,349,622,024 B = 59.930256 GiB** |
| `huggingface/` | 113 files · 64,178,670,067 B · 59.771044 GiB |
| `checkpoints/` | 12 files · 170,685,319 B · 0.158963 GiB (2 GRPO adapters) |
| `trajectories/` | 31 files · 266,638 B · 0.000248 GiB |

**This measurement is identical, byte for byte, to the independent measurement of the
R1 read-only iteration of the same day** (`docs/r1_readonly_evidence_report_20261114.md`,
§1, measured 2026-11-14T08:43:23Z–08:50:44Z). The cache is therefore unchanged
between that iteration and this one — nothing of this workstream wrote into it.

### 3.2 The pinned model revision — `VERIFIED`

| | |
|---|---|
| Repo / revision | `qtum/Qwen3-Coder-30B-A3B-Audit` @ `655425b794ae4a19f2ea16fa480c6b39102721ee` |
| Tree file | `huggingface/models--qtum--Qwen3-Coder-30B-A3B-Audit/trees/655425b7…21ee.json` |
| Size / SHA-256 | 6,512 B / `0f5245636ca4e61550365c8d39031339574f908bbdd96c82ba843451862582df` |

The digest is identical to the one recorded by the R1 iteration → the pinned cache is
intact and was read, not recomputed.

### 3.3 What is **not** proven by the inventory

* The presence of a file is **not** a proof that the model works. The manifest
  (`model_cache_manifest.json`) is written by the prefetch step (R2p), which has not
  run: the manifest is still absent, and the CPU service does not depend on it.
* The content SHA-256 of the 59.93 GiB of weights is **not** recomputed: that would
  mean reading the whole cache back out of the volume, which the read-only rule of
  this workstream forbids. The hub-declared digests of the R1 iteration stand.

---

## 4. Capacity and billing — `VERIFIED`

```powershell
modal billing summary --profile neubeginner
```

| Line | USD |
|---|---|
| Metered Cost | 6.02 |
| — Ephemeral Apps | 4.04 |
| — **Volumes** | **1.98** |
| — Deployed Apps / Network Egress | 0.00 / 0.00 |
| Free Storage | −1.98 |
| Credits | −4.04 |
| **Billed Cost** | **$0.00** |

| Measure | Value |
|---|---|
| Measured storage | 59.930256 GiB |
| Allowance (1 TiB/month, `modal.com/pricing`) | 1024 GiB |
| Allowance used | **5.85 %** |
| Headroom | **964.07 GiB** |

The storage of the workspace is fully covered by the published free allowance. The
account-wide concurrent peak in GiB is **not** observable: the control plane exposes no
account-wide storage gauge, and the billing API returns dollars, not GiB. The GiB
figures above are measured from the listing; the dollar figures come from the billing
API.

**After the deployment and the end-to-end run of this workstream the summary is
unchanged: `Billed Cost: $0.00`.**

---

## 5. The CPU service of this workstream — what exists after the inventory

| Object | Name | Note |
|---|---|---|
| Application | `aegis-rlvr-cpu-audit` | separate from the GPU application `aegis-rlvr-security` |
| App id | `ap-dhWbTc7uufRgnidkOz0WDW` | provider-issued |
| Deployment page | <https://modal.com/apps/neubeginner/main/deployed/aegis-rlvr-cpu-audit> | |
| Functions | `audit_contract`, `read_saved_result`, `probe_environment` | no GPU class, no web endpoint |
| Volumes | `aegis-model-cache` (read-only), `aegis-cpu-audit-results` (read-write) | |

The inventory was complete **before** any of these objects was created: the two
`modal deploy` attempts that failed during the build of the image (see
`docs/modal_deployment.md`, §7) created no volume and no lasting application — the
failed attempts are visible in the application history as stopped applications and
cost nothing.

---

## 6. Summary

| Deliverable of the inventory | Status |
|---|---|
| Modal CLI and SDK available | **VERIFIED** — 1.5.5 / 1.5.5 |
| Authorisation of the workspace | **VERIFIED** — reads and deployment executed |
| Applications of the workspace | **VERIFIED** — none before this workstream |
| Volume `aegis-model-cache` | **VERIFIED** — present, 247 entries, 59.930256 GiB, unchanged |
| Pinned cache readable | **VERIFIED** — tree file read, digest identical to the R1 measurement |
| Resource configuration and secrets | **VERIFIED** — the CPU service declares no secret and no GPU |
| SDK compatibility with the project | **VERIFIED** for this workstream (public object API only) |
| Model cache manifest | **UNAVAILABLE** — R2p has not run; not required by the CPU service |
| Content SHA-256 of the weights | **UNAVAILABLE** — would require a 59.93 GiB read-out |
| Account-wide concurrent storage peak | **UNAVAILABLE** — the control plane exposes no such gauge |
