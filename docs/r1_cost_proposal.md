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
| Network egress | **$0.04 / GiB** | the provider's plan-dependent allowance applies |

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
  worst case is **$78.93** (variant A in §5), with 120 s it is **$33.57**. The
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
  volume data-path traffic.
* **The prefetch's payload cap** is `pinned_bytes × (1 + R_download)` with
  `R_download = 1`: 61 077 997 602 bytes × 2 = **122 155 995 204 bytes**. With
  `R_download = 0` the cap would be the exact byte size and a transient failure
  would end the step (D20), so one retry allowance is proposed.

## 3. The per-stage estimate

The quantities come from the plan's trace table (§8.2.5): R3 = 1 invocation,
R3b ≤ 4, R4 ≤ 96 (32 GPU + 48 sandbox-CPU + 16 persistence). The **cumulative cold
containers** of a class are bounded by the invocation count — never by
`min(invocations, max_containers)` — because `max_containers` is a concurrency cap.

| stage | invocations | worst case | terms | proposed ceiling | headroom |
|---|---|---|---|---|---|
| **R2p** | 1 CPU | **$4.7823** | CPU $0.1981 · memory $0.0336 · egress $4.5507 · storage $0.0000 | **$5.00** | $0.2177 |
| **R3** | 1 sandbox-CPU | **$0.0147** | CPU $0.0126 · memory $0.0021 · egress $0.0000 · storage $0.0000 | **$0.10** | $0.0853 |
| **R3b** | 1 GPU + 2 sandbox + 1 persistence | **$0.4151** | GPU $0.3291 · CPU $0.0597 · memory $0.0261 · egress $0.0002 · storage $0.0000 | **$0.75** | $0.3349 |
| **R4** | 32 GPU + 48 sandbox + 16 persistence | **$12.9878** | GPU $10.5312 · CPU $1.6600 · memory $0.7928 · egress $0.0038 · storage $0.0000 | **$13.50** | $0.5122 |
| **sum** | | **$18.2000** | | **$19.35** | **$1.8000** vs the USD 20 cap |

Every proposed ceiling is at or above its stage's worst case, and the ceilings sum to
**$19.35 ≤ USD 20**, leaving **$0.65** of ceiling slack and **$1.80** of headroom
against the cap on the estimate itself. The storage term of every stage is **$0.00**:
the cycle's footprint stays inside the provider's free allowance (§4), and the
estimator allocates the storage cost back to the stages in proportion to their
footprint × duration share — so the sum of the per-stage totals is **exactly** the
cycle total and the standing baseline is never priced twice.

## 4. The storage term

* The volume's baseline at the start of the cycle is **0 GiB**; R2p writes the model
  cache (**56.888 GiB** = 61 077 997 602 bytes); the trajectories add **0.021 GiB**
  across the cycle. The cycle's **peak footprint is therefore 56.908 GiB** and its
  time-weighted footprint is **56.906 GiB**.
* The cycle's storage window is the **sum**: `T_exec` (20 400 s over the four
  stages) + the post-execution interval before the publication (86 400 s) + the
  retention (2 592 000 s = 30 days) = **34.236 days** → `months = 1 + ceil(34.236/28)
  = **3**` calendar months.
* The **footprint quantity** over that window is `Σ footprint × Δt / 28 days` =
  **69.58 GiB-month**; the free allowance is `1 024 GiB/month × 1.2227 month units`
  = **1 252.07 GiB-month**.
* The **billable** part is therefore `max(0, 69.58 − 1 252.07)` = **0.00 GiB-month**
  and the storage of the whole cycle costs **$0.0000**.

The bytes are priced **once**, over the cycle's window, and the allowance is offset
once. Pricing them in every stage's own window — the plan's per-stage formula applied
literally — would charge the same standing bytes four times: $61.4447 instead of
$15.3654. That is an over-count of the same bytes, not additional spend, and it is
why the per-stage ceilings above are built on the stages' *worst-case* terms, which
carry the **allocated** storage share.

The footprint is reported in every run, not only its cost: `peak_footprint_gib`,
`time_weighted_footprint_gib`, `footprint_gib_months`,
`free_allowance_gib_months`, `billable_gib_months` and the flag
`within_free_allowance`. A cycle that exceeds the allowance is billed for the excess
and its verdict becomes `BUDGET_INFEASIBLE` — the model never hides the excess.

## 5. The worst-case aggregate

The model has one answer, and it is the answer of the *actual charge*:

| | compute + egress | storage | **total** | headroom vs USD 20 |
|---|---|---|---|---|
| **the cycle** | $18.2000 | **$0.0000** (inside the 1 TiB/month allowance) | **$18.2000** | **+$1.8000** |

* **verdict: `WITHIN_BUDGET`**
* **status: `PROVISIONAL_ONLY / NOT_DISPATCHABLE`**

The status is `PROVISIONAL_ONLY / NOT_DISPATCHABLE` in every run: the rate card is not
approved, the bounds of §2 are candidates and not declarations, and no stage has an
approved step policy. The verdict is therefore *not* a permission to dispatch — it is
the arithmetic of the candidate bounds. A cycle that does not fit the cap is reported
as exactly **`BUDGET_INFEASIBLE`**, never as a number with a caveat.

For reference only — **not** the model of this proposal — the gross treatment that
ignores the published allowance would give `56.909 GiB × 3 months × $0.09/GiB·mo` =
$15.3654 of storage and a total of **$33.5654**, i.e. **$13.57 over the cap**. The
difference is entirely the storage term; the compute and the egress — the terms that
actually scale with the run — are $18.20 in both treatments. R1 does **not** weaken
any control to make the number fit: the controls (the explicit limits, the
container-count bound, the byte cap, the egress caps, the ceilings) are proposed as
they are.

Sensitivity of the aggregate:

| variant | compute + egress | total (allowance applied once) | vs USD 20 |
|---|---|---|---|
| **base (GPU timeout 120 s, `R_download = 1`)** | $18.2000 | **$18.2000** | **+$1.80** |
| the deployed GPU timeout 1200 s | $63.5640 | $63.5640 | −$43.56 |
| `R_download = 0` (no retry allowance for the prefetch) | $15.9246 | $15.9246 | +$4.08 |
| **the GPU payload cap is not zero** (see below) | $93.2860 | $93.2860 | −$73.29 |

**The sensitivity of the GPU egress bound.** The GPU class declares the
**provider-enforced** network blocking, so its payload cap is 0 — that is the branch
of the plan R1 takes. Modal's documentation does not state whether a *volume mount*
survives `block_network=True`, and the SDK does not validate the combination either.
The failure mode of an incompatible mount is **fail-closed** (the container cannot
read the model cache and the step fails), never an unbounded egress. But if the mount
turns out to be incompatible, the alternative branch applies: a conservative,
evidence-backed **non-zero** payload cap for the GPU containers — the size of the
pinned revision (**56.888 GiB** per container), the largest artefact a GPU container
holds. That variant is priced above: **$93.29** for the cycle, R3b **$2.69** and R4
**$85.80** against their ceilings — i.e. **`BUDGET_INFEASIBLE`**. The compatibility
has therefore to be confirmed before R3b/R4 are dispatched; the decision is the
maintainer's, and both branches are priced.

The measured anchor, for scale: the workspace's own published billing export
(`benchmarks/evidence/modal_billing_report_raw.json`, 2026-11-09) shows four
`aegis-rlvr-security` app sessions with **$1.1601 of H100 time, $0.0451 of CPU,
$0.0096 of memory and $0.0422 of egress** — **$1.26 in total** for the same shape of
workload, i.e. ≈6 % of the cap. The worst case is ~14× the measured spend, which is
what a worst case is for.

## 6. The decisions this proposal needs

1. **The candidate bounds of §2** — especially the GPU class timeout 1200 s → 120 s
   and the GPU startup timeout of 120 s. Without the first, the cycle's worst case
   is $63.56.
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

The **storage treatment is settled**: the provider's published 1 TiB/month allowance
is applied once to the cycle's footprint, so the storage of the run costs USD 0 while
the footprint stays inside it. The footprint is computed and reported in every run,
and an excess above the allowance is billed and flagged.

Until 1–4 are approved, the declared state stays fail-closed: the estimate is
unavailable and no step is dispatchable.
