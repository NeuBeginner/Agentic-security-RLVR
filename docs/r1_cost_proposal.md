# R1 — the cost proposal for R2p, R3, R3b and R4

**Status: PROPOSED. No stage ceiling is approved. No money has been spent.**

This document is the written cost proposal the maintainer asked for on 2026-11-11: the
assumptions, the per-stage ceilings that sum to no more than USD 20, the worst-case
aggregate and the remaining headroom — and, where the evidence does not support a
defensible estimate under USD 20, the precise report of that fact.

Everything is reproducible:

```
python -m benchmarks.r1_estimator --scenario benchmarks/evidence/r1_cost_scenario.json --provisional
```

(The `--provisional` flag only allows an **unapproved** rate card so that the proposal
can be computed; a real dispatch still refuses an unapproved rate card.)

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

The provider's published **1 TiB/month** volume allowance is deliberately **not**
netted out of the estimate (plan §8.2.5, input 8). Both treatments are shown in §5.

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

| stage | invocations | attributable estimate | terms | proposed ceiling |
|---|---|---|---|---|
| **R2p** | 1 CPU | **$4.7824** | CPU $0.1981 · memory $0.0336 · egress $4.5507 | **$5.00** |
| **R3** | 1 sandbox-CPU | **$0.0147** | CPU $0.0126 · memory $0.0021 · egress $0.0000 | **$0.10** |
| **R3b** | 1 GPU + 2 sandbox + 1 persistence | **$0.4150** | GPU $0.3291 · CPU $0.0597 · memory $0.0261 · egress $0.0002 | **$0.75** |
| **R4** | 32 GPU + 48 sandbox + 16 persistence | **$12.9878** | GPU $10.5312 · CPU $1.6600 · memory $0.7928 · egress $0.0038 | **$13.50** |
| **sum** | | **$18.2000** | | **$19.35** |

Every proposed ceiling is at or above its stage's estimate, and the ceilings sum to
**$19.35 ≤ USD 20**, leaving **$0.65** of ceiling slack and **$1.80** of headroom
against the cap on the estimate itself.

## 4. The storage term

* The volume's baseline at the start of the cycle is **0 GiB**; R2p writes the model
  cache (**56.888 GiB** = 61 077 997 602 bytes); the trajectories add **0.021 GiB**
  across the cycle. The cycle's volume is therefore **56.909 GiB**.
* The cycle's storage window is the **sum**: `T_exec` (20 400 s over the four
  stages) + the post-execution interval before the publication (86 400 s) + the
  retention (2 592 000 s = 30 days) = **31.236 days** → `months = 1 + ceil(31.236/28)
  = **3**` calendar months.
* The gross storage term is therefore `56.909 GiB × 3 months × $0.09/GiB·mo` =
  **$15.3654**.

The volume's bytes are priced **once**, over the cycle's window. Pricing them in
every stage's own window — the plan's per-stage formula applied literally — would
charge the same standing bytes four times: $61.4447 instead of $15.3654. That is an
over-count of the same bytes, not additional spend, and it is why the per-stage
ceilings above are built on the stages' *attributable* terms.

## 5. The worst-case aggregate

| treatment | compute + egress | storage | **total** | headroom vs USD 20 |
|---|---|---|---|---|
| **A — the plan's literal gross method** (the allowance is not netted out) | $18.2000 | $15.3654 | **$33.5654** | **−$13.5654** |
| **B — the actual charge** (the published 1 TiB/month allowance covers the 56.9 GiB cache entirely) | $18.2000 | $0.0000 | **$18.2000** | **+$1.8000** |

**This is the report the maintainer asked for.** Under treatment A the worst-case
aggregate of the whole cycle is **$33.57**, i.e. **$13.57 over the USD 20 cap**, and
under the plan's literal per-stage formula the per-stage ceilings would have to sum
to about **$79.6**. Under treatment B the cycle's worst case is **$18.20**, which
fits under the cap with $1.80 of headroom.

**Treatment A is not affordable under USD 20.** The gap is entirely the
volume-storage term ($15.37 of $33.57); the compute and the egress — the terms that
actually scale with the run — are $18.20. R1 does **not** weaken any control to make
the number fit: the controls (the explicit limits, the container-count bound, the
byte cap, the egress caps, the ceilings) are all proposed as they are, and the
residual is reported here for the maintainer's decision.

Sensitivity of the aggregate:

| variant | compute + egress | gross total | vs USD 20 |
|---|---|---|---|
| base (GPU timeout 120 s, `R_download = 1`) | $18.2000 | $33.5654 | −$13.57 |
| **the deployed GPU timeout 1200 s** | $63.5640 | $78.9294 | −$58.93 |
| `R_download = 0` (no retry allowance for the prefetch) | $15.9246 | $31.2901 | −$11.29 |

The measured anchor, for scale: the workspace's own published billing export
(`benchmarks/evidence/modal_billing_report_raw.json`, 2026-11-09) shows four
`aegis-rlvr-security` app sessions with **$1.1601 of H100 time, $0.0451 of CPU,
$0.0096 of memory and $0.0422 of egress** — **$1.26 in total** for the same shape of
workload, i.e. ≈6 % of the cap. The worst case is ~27× the measured spend, which is
what a worst case is for.

## 6. The decisions this proposal needs

1. **The candidate bounds of §2** — especially the GPU class timeout 1200 s → 120 s
   and the GPU startup timeout of 120 s. Without the first, the cycle's worst case
   is $78.93.
2. **The storage treatment.** Either the allowance is netted out (treatment B: the
   actual charge is $0, the cycle is $18.20) or the plan's conservative gross method
   stands (treatment A: $33.57, over the cap) — in which case either the scope of R4
   shrinks or the cap has to rise. **R1 does not choose.**
3. **The per-stage ceilings** of §3 (sum $19.35) and the per-stage wall-clock
   budgets and post-execution deadlines that the dispatch gate requires: R3 and R3b
   20 minutes each (plan §8.2.5), R4 **4 hours** (the plan declares none today) and
   a **24-hour** post-execution deadline for every stage (the plan declares none
   today — D28 makes the volume term unavailable without it).
4. **`R_download`** for the prefetch (1 proposed) and the **protocol allowance**
   (1 MiB per container proposed).

Until 1–4 are approved, the declared state stays fail-closed: the estimate is
unavailable and no step is dispatchable.
