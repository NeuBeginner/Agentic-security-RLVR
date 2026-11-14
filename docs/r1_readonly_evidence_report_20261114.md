# R1 read-only evidence report — 2026-11-14

**Scope of this iteration:** evidence collection only. No execution, no dispatch, no spend.

| | |
|---|---|
| Repository | `NeuBeginner/Agentic-security-RLVR` |
| PR | #14 (Draft) — `docs/evidence-regeneration-architecture-plan` |
| Reviewed head | `c9f3e1b121cf212ff1aa348fa2c26627f0d79056` |
| Stage status | R1 — **NOT ACCEPTED / PROVISIONAL_ONLY / NOT_DISPATCHABLE** (unchanged) |
| Provider | Modal — workspace `neubeginner`, environment `main`, profile `neubeginner` |
| Modal client | 1.5.5 · Python 3.10.11 · Windows 10.0.22631 x64 |
| Collection window (UTC) | 2026-11-14T08:43:23Z … 2026-11-14T08:50:44Z |
| Machine-readable report | `benchmarks/evidence/r1_readonly_evidence_20261114.json` |
| Raw outputs | `benchmarks/evidence/r1_readonly_20261114/` |

---

## 0. Read-only guarantee

Only these operations were used:

| Operation | Kind |
|---|---|
| `Volume.iterdir(path, recursive=True/False)` | read |
| `Volume.read_file(path)` (2 small metadata files) | read |
| `FunctionGet` RPC | read |
| `modal volume list` / `modal volume ls` / `modal app list` / `modal app history` / `modal billing summary` / `modal billing report` | read |

Nothing was deployed, served, run, invoked, dispatched, downloaded, written, committed,
removed or paid for. `PINNED_PUBLIC_KEY` stays `null`, no approval artifact was created
or signed, the rate card stays unapproved, no `Unset` bound was changed, R2p/R3/R3b/R4
were not executed, the dispatch gate was not touched, the PR stays **Draft**.

---

## 1. Storage baseline and account capacity — `VERIFIED`

**Provenance:** `modal volume list`; `modal volume ls aegis-model-cache`; SDK
`Volume.iterdir`; `modal billing summary` (this month). Raw: `volume_inventory.json`,
`raw_cli_outputs.txt`.

The volume exists: `aegis-model-cache`, created by `neubeginner` on 2026-10-31 09:42 CET.

**Two independent listings agree byte-for-byte** (`listing_agreement: IDENTICAL`):

| Method | Entries |
|---|---|
| A — one recursive listing from the root | 247 |
| B — breadth-first walk, one level per call | 247 |

| Measure | Value |
|---|---|
| Entries | 247 = 156 files + 42 directories + 49 symlinks |
| **Total file bytes** | **64,349,622,024 B = 59.930256 GiB** |
| `huggingface/` | 113 files · 64,178,670,067 B · 59.771044 GiB |
| `checkpoints/` | 12 files · 170,685,319 B · 0.158963 GiB (2 GRPO adapters) |
| `trajectories/` | 31 files · 266,638 B · 0.000248 GiB |

**Account-wide:** the workspace contains exactly **one** volume (`aegis-model-cache`),
so the measured total *is* the account-wide volume footprint.

**Against the 1 TiB (1024 GiB) monthly allowance** (source: `modal.com/pricing`,
"Volumes $0.09 / GiB / mo *includes 1 TiB / mo free*", read 2026-11-11):

| Measure | Value |
|---|---|
| Measured usage | 59.930256 GiB |
| Allowance used | 5.85 % |
| Headroom | 964.069744 GiB |
| Within allowance | **yes** |

**Billing corroboration** (`modal billing summary`, this month):

| Line | USD |
|---|---|
| Metered Cost | 6.02 |
| — Ephemeral Apps | 4.04 |
| — **Volumes** | **1.98** |
| — Deployed Apps / Network Egress | 0.00 / 0.00 |
| Credits | −4.04 |
| **Free Storage** | **−1.98** |
| **Billed Cost** | **$0.00** |

The storage is fully covered by the published free-storage allowance for this month.

**`UNAVAILABLE` sub-items** (not measured, not estimated):

- *Account-wide concurrent peak in GiB* — the Modal control plane exposes no
  account-wide storage gauge. The value above is the instantaneous inventory; the
  billing API confirms it stays inside the allowance. **An explicit operator
  attestation can substitute for this sub-item.**
- *A GiB figure from the billing API* — the billing API returns metered dollars, not
  GiB. The GiB numbers here are **measured from the listing**, not derived from the
  price; the dollar figures are from the billing API.

The baseline is therefore **not zero**: the cycle starts from 59.93 GiB already stored.

---

## 2. Pinned model cache — byte count `VERIFIED`, manifest and content SHA-256 `UNAVAILABLE`

**Provenance:** the hub cache's own tree file for the pinned revision, read read-only
from the volume, plus the volume listing. Raw: `pinned_cache_verification.json`,
`pinned_trees_raw.json`.

| | |
|---|---|
| Repo / revision | `qtum/Qwen3-Coder-30B-A3B-Audit` @ `655425b794ae4a19f2ea16fa480c6b39102721ee` |
| Tree file | `huggingface/models--qtum--Qwen3-Coder-30B-A3B-Audit/trees/655425b7…21ee.json` |
| Tree file size / SHA-256 | 6,512 B / `0f5245636ca4e61550365c8d39031339574f908bbdd96c82ba843451862582df` |
| Tree entries | 25 |

The cache stores large LFS/Xet payloads in a **shared blob store**
(`huggingface/blobs/<xx>/<hash>`); the per-repository directory holds symlinks into it.
Each tree entry was therefore matched by blob key (`xet_hash` → `lfs_sha256` → `blob_id`)
and by **exact byte size**.

| Group | Entries | Bytes | Result |
|---|---|---|---|
| Weight shards `model-00001…00017-of-00017.safetensors` | 17 | 61,066,574,952 | **17/17 verified, 0 size mismatches** |
| `tokenizer.json` | 1 | 11,422,650 | **verified** |
| Other small files (`config.json`, `generation_config.json`, `chat_template.jinja`, `tokenizer_config.json`, `model.safetensors.index.json`) | 5 | 1,707,901 | **verified** |
| **Total verified** | **23** | **61,079,705,503** | |
| `.gitattributes` | — | 1,570 | absent |
| `README.md` | — | 13,570 | absent |

**Reconciliation with the declared expectation** (`core.r1_bounds.PINNED_MODEL.bytes_total`):

```
61,066,574,952 (17 shards) + 11,422,650 (tokenizer.json)
  = 61,077,997,602 B  ==  the declared 61,077,997,602 B      EXACT MATCH
```

The two absent entries (15,140 B total) are documentation files of the revision; they
are not required for inference and no snapshot symlink points at them.

**Staging leftovers — reported separately:**

| Kind | Count | Bytes | Status |
|---|---|---|---|
| True staging leftovers (`.incomplete`, `.tmp`, `.partial`, `.staging`, `.pending`) | **0** | 0 | **VERIFIED — none present** |
| Hub lock files (`*.lock`) | 49 | 0 | hub bookkeeping |
| Hub reference files (`*.refs`) | 19 | 2,111 | hub bookkeeping |
| Files under `huggingface/.locks/` | 30 | 0 | hub bookkeeping |

**`UNAVAILABLE` sub-items:**

- **R2p manifest** — `model_cache_manifest.json` does **not** exist on the volume. The
  manifest is written by the R2p prefetch step, which R1 does not run; its absence is
  expected and does not condemn the cache. It cannot be verified in this iteration.
- **Content SHA-256** — the SHA-256 of every shard is *recorded* from the hub-declared
  `lfs_sha256`, but **not recomputed**: re-hashing means reading ~59.9 GiB back out of
  the volume, which the read-only instruction forbids. The hub-declared digests are
  carried in `pinned_cache_verification.json` per file.

---

## 3. Modal autoscaler read-back — `UNAVAILABLE`

**Provenance:** read-only `FunctionGet` RPC on `ProductionAuditAgent.*`. Raw:
`autoscaler_readback.json`.

```
NotFoundError: App 'aegis-rlvr-security' not found in environment 'main'
```

Corroboration, all read-only:

- `modal app list --json` → `[]` (nothing running, deployed or recently stopped)
- `modal app history aegis-rlvr-security` → *No App with name 'aegis-rlvr-security'
  found in the 'main' environment.*
- `modal billing report --for "last month"` → apps named `aegis-rlvr-security` were
  deployed in this workspace on 2026-10-30/31 and are no longer listed

| Field | Status |
|---|---|
| `function` | `UNAVAILABLE` |
| `autoscaler_settings` | `UNAVAILABLE` |
| `min_containers` / `max_containers` / `buffer_containers` / `scaledown_window` | `UNAVAILABLE` |

There is no deployed function to read back. `update_autoscaler()` was **not** called.

### 3.1 A defect found while collecting this evidence

The repository's own reader cannot perform this read against Modal SDK 1.5.5:

| | |
|---|---|
| File / line | `benchmarks/r1_dispatch.py:350` |
| Code | `client = await Client.from_env()` |
| Problem | SDK 1.5.5 defines `Client = synchronize_api(_Client)` (`modal/client.py:532`), so the public client is **synchronous** |
| Observed error | `TypeError: object Client can't be used in 'await' expression` |
| Effect | `provider_autoscaler_reader` always fails closed with `AutoscalerReadbackUnavailable`, **independently of the deployment state** |

The failure is fail-closed and therefore safe, but it means the D27 read-back could
never succeed against SDK 1.5.5 even for a deployed app — the read-back would have to
be re-attempted after a deployment exists. This is **reported, not fixed**: this
iteration is documentation/evidence only, and the R1 contract forbids changing the
dispatch gate.

---

## 4. Evidence integrity — `VERIFIED`

- No historical evidence file was rewritten; `historical_evidence_touched` is empty.
- No declared digest was altered and no estimator assumption was changed to make a
  result pass.
- Every number in this report is reproducible from the raw artifacts stored next to
  it: `benchmarks/evidence/r1_readonly_20261114/` (raw JSON/CLI outputs plus the
  collection scripts that produced them).
- The two methods that measured the volume listing agree exactly, so the byte total
  cannot be an artefact of a duplicated or truncated listing.

---

## 5. Status summary

| Deliverable | Status |
|---|---|
| Storage baseline (volume inventory) | **VERIFIED** — 64,349,622,024 B / 59.930256 GiB |
| Account capacity vs the 1 TiB allowance | **VERIFIED** — 5.85 % used, 964.07 GiB headroom, billed $0.00 |
| Account-wide concurrent peak (GiB gauge) | **UNAVAILABLE** — API exposes none; operator attestation may substitute |
| Pinned cache byte count | **VERIFIED** — exact match to 61,077,997,602 B (17 shards + tokenizer) |
| Pinned cache manifest | **UNAVAILABLE** — R2p has not written it |
| Pinned cache content SHA-256 | **UNAVAILABLE** — recomputation needs a 59.9 GiB read-out |
| Staging leftovers | **VERIFIED** — none; hub lock/ref metadata reported separately |
| Autoscaler read-back | **UNAVAILABLE** — no deployed app; plus an SDK defect in the repository reader |
| Evidence integrity | **VERIFIED** |

## 6. What this iteration does *not* do

R1 remains **NOT ACCEPTED / PROVISIONAL_ONLY / NOT_DISPATCHABLE**. This report closes
the *read-only* evidence gaps named in the review comment; it does not accept R1, does
not unblock any stage, and does not authorise R2p/R3/R3b/R4. The PR stays **Draft**.
