# R1 — the cost proposal for R2p, R3, R3b and R4

**Status: PROPOSED — `PROVISIONAL_ONLY / NOT_DISPATCHABLE`. No stage ceiling is
approved. No money has been spent.**

This document is the written cost proposal the maintainer asked for on 2026-11-11: the
assumptions, the per-stage ceilings that sum to no more than USD 20, the worst-case
aggregate and the remaining headroom — and, where the evidence does not support a
defensible estimate under USD 20, the precise report of that fact.

Everything is reproducible by **one** command — the one authoritative producer of the
numbers of this proposal:

```
python -m benchmarks.r1_estimator --scenario benchmarks/evidence/r1_cost_scenario.json --provisional
```

(The `--provisional` flag only allows an **unapproved** rate card so that the proposal
can be computed; a real dispatch still refuses an unapproved rate card. `--json`
prints the same numbers as a machine-readable record.)

## 1. The rates

The rates are an approval input, never a repository constant. The card is
`benchmarks/evidence/r1_rate_card.json`, read from **modal.com/pricing** on
**2026-11-11**:

| rate class | rate | note |
|---|---|---|
| CPU | **$0.0000131 / core / s** | physical core (2 vCPU equivalent), minimum 0.125 cores per container |
| Memory | **$0.00000222 / GiB / s** | minimum request 128 MiB per container |
| GPU (H100) | **$0.001097 / s** | $3.9492 per GPU-hour |
| Volume storage | **$0.09 / GiB / month** | includes 1 TiB/month free |
| Network **egress** (outbound) | **$0.04 / GiB** | the provider's plan-dependent allowance applies |
| Network **ingress** (inbound) | **$0.00 / GiB** | the provider bills **outbound** traffic as egress; a download into the container is ingress and is not billed at the egress rate, and reads/writes of Modal Volumes are not egress either (<https://modal.com/docs/guide/network-egress-billing>, read 2026-11-12) |

Two facts from the same page are used below: the provider bills "during application
load time and during the time your container is processing inputs", and it keeps
containers alive for **60 seconds** after the last input by default (billed) — that
default is the candidate `scaledown_window`.

The provider's published **1 TiB/month** volume allowance is applied **once**, to the
cycle's time-weighted footprint (§4). Inside the allowance the storage of the run
costs **USD 0**; the footprint is still computed and reported, and the part above the
allowance would be billed and flagged. The allowance is an **account-level monthly**
allowance, so it belongs to the account and not to a stage — pricing it per stage
would credit the same free gigabytes four times.

**The baseline of §4 is measured; the capacity proof is available, with open sub-items.**
The read-only inventory of 2026-11-14 measured the existing baseline of this
workspace's remote Volume: **64 349 622 024 bytes = 59.930256 GiB**. The cost
assumption of USD 0 is kept, and the proof that the cycle fits the account now
**rests on that measurement** — the estimator verifies the scenario against the
evidence file it cites and refuses a baseline that is not the measured one.

## 2. The candidate bounds

These are **candidates for approval**; the declared values in `core/r1_bounds.py`
stay required-but-unset until they are approved (see `docs/r1_bounds_contract.md`).

| class | cpu request / limit | memory request / limit | timeout | startup_timeout | scaledown_window | `T_billable` |
|---|---|---|---|---|---|---|
| sandbox CPU | 2.0 / **4.0** | 2048 MiB / **4096 MiB** | 60 s | **120 s** | **60 s** | 240 s |
| GPU class | 4.0 / **8.0** | 16384 MiB / **32768 MiB** | **120 s** | **120 s** | **60 s** | 300 s |
| persistence | 0.5 / **1.0** | 512 MiB / **1024 MiB** | 60 s | **120 s** | **60 s** | 240 s |
| prefetch (R2p, sandbox CPU) | 2.0 / **4.0** | 2048 MiB / **4096 MiB** | **3600 s** | **120 s** | **60 s** | 3780 s |

Why each candidate:

* **The GPU class timeout is reduced from the deployed 1200 s to 120 s.** This is the
  single largest lever in the whole proposal: with the deployed value the cycle's
  worst case is **$59.01** (variant A in §5), with 120 s it is **$13.65**. The
  published configuration to preserve is the runner's `timeout_sec = 120`
  (plan §10.1) — the *provider-side* function timeout is not part of it, it only
  bounds the container's billable life. The measured evidence supports 120 s: the
  workspace's own billing export shows **677 GPU-seconds across 30 GPU containers**
  for the published run, i.e. **≈22.6 s of billed life per container**, model load
  included. A container that needs more than 120 s fails closed (the step fails, it
  is not retried — D20).
* **The GPU startup timeout is 120 s.** The startup is the dominant term of
  `T_billable` for the GPU class (120 s of 300 s), and it is billed. 120 s is ≈5× the
  measured per-container life; a slower cold start fails the container closed.
* **The GPU memory limit is 32 GiB.** The pinned model is 61 GiB in bf16, but it is
  loaded onto the GPU's HBM (`device_map="auto"`, safetensors are mmapped from the
  volume), so the container's RAM is the loader's working set, not the model. If the
  loader's peak RAM is larger than 32 GiB, the container is OOM-killed — that is the
  residual risk of this candidate, and it fails the step rather than the budget.
* **The sandbox memory limit is 4096 MiB.** The plan states that a `forge` compile of
  the published targets is not bounded by 2048 MiB, so the limit must not be the
  request; 2× the published request is the smallest round candidate that keeps the
  request as the floor of the bill.
* **The CPU limits are 2× the requests.** The sandbox's published request is 2.0
  cores, the persistence function's is unset (it runs on the platform default of
  0.125 cores today), the GPU container's is unset (also the 0.125-core default).
* **`scaledown_window = 60 s`** is the provider's published default, made explicit.
* **The prefetch's protocol allowance** is 1 MiB per container: the workspace's
  billing export shows **$0.00013117 of network egress (3.35 MB)** for a whole app
  session on 2026-11-09 — the measured order of magnitude of the control-plane and
  volume data-path traffic. This is the whole **outbound** traffic of a container.
* **The prefetch's inbound cap** is `pinned_bytes × (1 + R_download)` with
  `R_download = 1`: 61 077 997 602 bytes × 2 = **122 155 995 204 bytes**. With
  `R_download = 0` the cap would be the exact byte size and a transient failure
  would end the step (D20), so one retry allowance is proposed. These bytes are
  **ingress**: the model is downloaded into the container and written to the volume,
  and neither the download nor the volume write is egress. They are declared
  separately (`core.r1_bounds.INGRESS_POLICIES`) and priced at the ingress rate of
  **$0.00 / GiB** — never at the outbound egress rate.

## 3. The per-stage estimate

The quantities come from the plan's trace table (§8.2.5): R3 = 1 invocation,
R3b ≤ 4, R4 ≤ 96 (32 GPU + 48 sandbox-CPU + 16 persistence). The **cumulative cold
containers** of a class are bounded by the invocation count — never by
`min(invocations, max_containers)` — because `max_containers` is a concurrency cap.

| stage | invocations | worst case | terms | proposed ceiling | headroom |
|---|---|---|---|---|---|
| **R2p** | 1 CPU | **$0.2317** | CPU $0.1981 · memory $0.0336 · egress $0.0000 · ingress $0.0000 · storage $0.0000 | **$5.00** | $4.7683 |
| **R3** | 1 sandbox-CPU | **$0.0147** | CPU $0.0126 · memory $0.0021 · egress $0.0000 · storage $0.0000 | **$0.10** | $0.0853 |
| **R3b** | 1 GPU + 2 sandbox + 1 persistence | **$0.4151** | GPU $0.3291 · CPU $0.0597 · memory $0.0261 · egress $0.0002 · storage $0.0000 | **$0.75** | $0.3349 |
| **R4** | 32 GPU + 48 sandbox + 16 persistence | **$12.9878** | GPU $10.5312 · CPU $1.6600 · memory $0.7928 · egress $0.0038 · storage $0.0000 | **$13.50** | $0.5122 |
| **sum** | | **$13.6493** | | **$19.35** | **$6.3507** vs the USD 20 cap |

Every proposed ceiling is at or above its stage's worst case, and the ceilings sum to
**$19.35 ≤ USD 20**, leaving **$0.65** of ceiling slack and **$6.35** of headroom
against the cap on the estimate itself. The storage term of every stage is **$0.00**:
the cycle's footprint stays inside the provider's free allowance (§4), and the
estimator allocates the storage cost back to the stages in proportion to their
footprint × duration share — so the sum of the per-stage totals is **exactly** the
cycle total and the standing baseline is never priced twice.

**The ingress term of R2p is $0.0000, and that is the point.** The prefetch's
**122 155 995 204 bytes** of model download are *inbound* traffic: the provider bills
outbound traffic as egress, and a download into the container is not egress
(<https://modal.com/docs/guide/network-egress-billing>, read 2026-11-12). Pricing them
at the outbound rate would have charged **$4.5507** for bytes the provider does not
bill as egress. The bytes are still **bounded** — the inbound cap is a declared bound
of R2p and an approval input — they are simply not priced as egress.

## 4. The storage term

**What is measured and what is assumed.** Three different things are kept apart, and
the estimator reports the state of each one in every run:

| quantity | state | value |
|---|---|---|
| the **baseline** of the remote Volume | **MEASURED** — the read-only inventory of 2026-11-14: two independent listings (one recursive, one breadth-first) agree byte-for-byte, 247 entries. Evidence: `benchmarks/evidence/r1_readonly_evidence_20261114.json` and `docs/r1_readonly_evidence_report_20261114.md`, §1 | 64 349 622 024 bytes = 59.930256 GiB |
| the **measured local bytes** | **measured** — the tracked artifacts tree of this repository (159 files) on 2026-11-12, `git cat-file -s` | 5 034 779 bytes = 0.004689 GiB |
| the **increment of a future run** | **CANDIDATE ESTIMATE** — the artefacts a future run would write; the published run's tracked artifacts (0.004689 GiB) anchor the order of magnitude, the values are not measured | 56.888 GiB (model cache) + 0.001 GiB (R3b) + 0.02 GiB (R4) |

The arithmetic below therefore rests on a **measured** baseline, and every step starts
from the footprint the previous step left behind — a step that declares a different
baseline fails closed. The *cost* of the storage is USD 0.00 (inside the allowance),
and the **capacity proof** — that the cycle fits this account — is **AVAILABLE**: the
workspace holds exactly **one** Volume, so the measured total *is* the account-wide
footprint, and against the published `< 1 TiB/month` (`1 024 GiB/month`) allowance the
account uses 5.85 % with 964.07 GiB of headroom; the billing summary of the same
month corroborates it (volumes metered 1.98 USD, fully covered by the free storage
allowance, billed 0.00 USD). The estimator says so in `storage_capacity_proof`,
`storage_capacity_proof_reasons` and `storage_capacity_proof_residuals`; it does not
present the footprint as a measurement.

**The open sub-items of the proof** — they do not make it unavailable, and they are
reported next to it in every run:

1. **The account-wide concurrent storage peak has no API gauge.** The measured total
   is an instantaneous inventory; the monthly billing confirms that the account stays
   inside the allowance. An explicit operator attestation may substitute for this
   sub-item.
2. **Post-R2p model-cache manifest and Volume byte read-back:** confirmation that the
   materialised revision `655425b794ae4a19f2ea16fa480c6b39102721ee` of
   `qtum/Qwen3-Coder-30B-A3B-Audit` on `aegis-model-cache` equals the pinned
   `61 077 997 602 bytes` (`56.888 GiB`) with no leftover staging files.
3. **Post-R3b/R4 trajectory footprint and post-retention deletion verification:**
   confirmation that incremental trajectory bytes stay within the `0.021 GiB` candidate
   bound and are deleted after the 30-day retention window.

* The volume's baseline at the start of the cycle is **measured**: 59.930256 GiB; R2p
  writes the model cache (**56.888 GiB** = 61 077 997 602 bytes) as the conservative
  **cold-cache worst case**; the trajectories add a **candidate** 0.021 GiB across the
  cycle. The cycle's **candidate peak footprint is therefore 116.839 GiB** and its
  candidate time-weighted footprint is **116.837 GiB**.

  The pinned bytes are counted **twice** here, on purpose: the measured baseline
  already contains the pinned revision (23/23 files, byte-exact), so in the measured
  state the prefetch would write only the manifest. The cold-cache worst case is kept
  because the prefetch function is not implemented yet and its behaviour on an
  already materialised cache is not verified. The peak is an **upper bound** of the
  cycle, not a prediction of it.
* The cycle's storage window is the **sum**: `T_exec` (20 400 s over the four
  stages) + the post-execution interval before the publication (86 400 s) + the
  retention (2 592 000 s = 30 days) = **34.236 days** → `months = 1 + ceil(34.236/28)
  = **3**` calendar months.
* The **footprint quantity** over that window is `Σ footprint × Δt / 28 days` =
  **142.86 GiB-month**; the free allowance is `1 024 GiB/month × 1.2227 month units`
  = **1 252.06 GiB-month**.
* The **billable** part is therefore `max(0, 142.86 − 1 252.06)` = **0.00 GiB-month**
  and the storage of the whole cycle costs **$0.0000**.

The bytes are priced **once**, over the cycle's window, and the allowance is offset
once. Pricing them in every stage's own window — the plan's per-stage formula applied
literally — would charge the same standing bytes four times: $115.6597 instead of
$31.5465. That is an over-count of the same bytes, not additional spend, and it is
why the per-stage ceilings above are built on the stages' *worst-case* terms, which
carry the **allocated** storage share.

The footprint is reported in every run, not only its cost: `peak_footprint_gib`,
`time_weighted_footprint_gib`, `footprint_gib_months`,
`free_allowance_gib_months`, `billable_gib_months` and the flag
`within_free_allowance`. A cycle that exceeds the allowance is billed for the excess
and its verdict becomes `BUDGET_INFEASIBLE` — the model never hides the excess. The
**state** of the footprint is reported next to it: `baseline_status`,
`incremental_status`, `capacity_proof`, `capacity_proof_reasons` and
`capacity_proof_residuals`.

## 5. The worst-case aggregate

The model has one answer, and it is the answer of the *actual charge*:

| | compute + egress + ingress | storage | **total** | headroom vs USD 20 |
|---|---|---|---|---|
| **the cycle** | $13.6493 | **$0.0000** (inside the 1 TiB/month allowance) | **$13.6493** | **+$6.3507** |

* **verdict: `WITHIN_BUDGET`**
* **status: `PROVISIONAL_ONLY / NOT_DISPATCHABLE`**
* **storage capacity proof: `AVAILABLE`** (the baseline of the remote Volume is
  measured and verified against its evidence file — see §4; three sub-items of the
  proof stay open and are reported next to it)

The status is `PROVISIONAL_ONLY / NOT_DISPATCHABLE` in every run: the rate card is not
approved, the bounds of §2 are candidates and not declarations, and no stage has an
approved step policy. The verdict is therefore *not* a permission to dispatch — it is
the arithmetic of the candidate bounds. A cycle that does not fit the cap is reported
as exactly **`BUDGET_INFEASIBLE`**, never as a number with a caveat.

For reference only — **not** the model of this proposal — the gross treatment that
ignores the published allowance would give `116.839 GiB × 3 months × $0.09/GiB·mo` =
$31.5465 of storage and a total of **$45.1958**. Pricing the same standing bytes in
every stage's own window instead of once over the cycle charges them four times over
— $115.6597 with the same month treatment per stage (2 months for R2p/R3/R3b/R4,
3 months for the 30-day retention). The difference is entirely the storage term; the
compute, the egress and the ingress — the terms that actually scale with the run —
are $13.65 in both treatments. R1 does **not** weaken any control to
make the number fit: the controls (the explicit limits, the container-count bound, the
byte cap, the ingress and egress caps, the ceilings) are proposed as they are.

Sensitivity of the aggregate:

| variant | compute + egress + ingress | total (allowance applied once) | vs USD 20 |
|---|---|---|---|
| **base (GPU timeout 120 s, `R_download = 1`)** | $13.6493 | **$13.6493** | **+$6.35** |
| the deployed GPU timeout 1200 s | $59.0133 | $59.0133 | −$39.01 |
| `R_download = 0` (no retry allowance for the prefetch) | $13.6493 | $13.6493 | +$6.35 |
| **the GPU payload cap is not zero** (see below) | $88.7415 | $88.7415 | −$68.74 |

**The `R_download` variant no longer moves the cost.** The model download is
**ingress**, and ingress is not billed at the egress rate: halving the inbound cap
changes the *bound*, not the price. (Before the ingress was separated, the same
variant moved the total by $2.28 — that was the price of the model download being
charged as egress.)

**The sensitivity of the GPU egress bound.** The GPU class declares the
**provider-enforced** network blocking, so its payload cap is 0 — that is the branch
of the plan R1 takes. Modal's documentation does not state whether a *volume mount*
survives `block_network=True`, and the SDK does not validate the combination either.
The failure mode of an incompatible mount is **fail-closed** (the container cannot
read the model cache and the step fails), never an unbounded egress. But if the mount
turns out to be incompatible, the alternative branch applies: a conservative,
evidence-backed **non-zero** payload cap for the GPU containers — the size of the
pinned revision (**56.888 GiB** per container), the largest artefact a GPU container
holds. That variant is priced above: **$88.74** for the cycle, R3b **$2.69** and R4
**$85.80** against their ceilings — i.e. **`BUDGET_INFEASIBLE`**. The compatibility
has therefore to be confirmed before R3b/R4 are dispatched; the decision is the
maintainer's, and both branches are priced.

The measured anchor, for scale: the workspace's own published billing export
(`benchmarks/evidence/modal_billing_report_raw.json`, 2026-11-09) shows four
`aegis-rlvr-security` app sessions with **$1.1601 of H100 time, $0.0451 of CPU,
$0.0096 of memory and $0.0422 of egress** — **$1.26 in total** for the same shape of
workload, i.e. ≈6 % of the cap. The worst case is ~11× the measured spend, which is
what a worst case is for.

## 6. The decisions this proposal needs

1. **The candidate bounds of §2** — especially the GPU class timeout 1200 s → 120 s
   and the GPU startup timeout of 120 s. Without the first, the cycle's worst case
   is $59.01.
2. **The per-stage ceilings** of §3 (sum $19.35) and the per-stage wall-clock
   budgets and post-execution deadlines that the dispatch gate requires: R3 and R3b
   20 minutes each (plan §8.2.5), R4 **4 hours** (the plan declares none today) and
   a **24-hour** post-execution deadline for every stage (the plan declares none
   today — D28 makes the volume term unavailable without it).
3. **`R_download`** for the prefetch (1 proposed) and the **protocol allowance**
   (1 MiB per container proposed).
4. **The GPU network bound.** The declaration is the provider-enforced
   `block_network=True` of the GPU class, whose payload cap is therefore 0. The
   compatibility of a volume mount with `block_network=True` is not documented by
   Modal and has to be confirmed before R3b/R4 are dispatched; the alternative — a
   conservative non-zero cap — is priced in §5 and is `BUDGET_INFEASIBLE`.
5. **The capacity preflight of the storage.** The cost assumption of USD 0 is kept, and
   the proof that the cycle fits this account now rests on the **measured** baseline
   (64 349 622 024 B = 59.930256 GiB, read-only inventory of 2026-11-14, verified by
   the estimator against the evidence file it cites). The proof is **AVAILABLE**; what
   is still open is its three sub-items: the account-wide concurrent peak gauge (no
   API), the post-R2p manifest and footprint read-back, and the post-R3b/R4 trajectory
   measurement. They are reported next to the proof in every run.

The **storage treatment is settled**: the provider's published 1 TiB/month allowance
is applied once to the cycle's footprint, so the storage of the run costs USD 0 while
the footprint stays inside it. The footprint is computed from a **measured** baseline
and reported with its state (`baseline_status`, `incremental_status`,
`capacity_proof`, `capacity_proof_residuals`) in every run, and an excess above the
allowance is billed and flagged.

Until 1–5 are approved, the declared state stays fail-closed: the estimate is
unavailable and no step is dispatchable.
