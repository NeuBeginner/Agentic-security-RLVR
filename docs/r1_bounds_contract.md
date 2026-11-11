# R1 — the resource, lifecycle, autoscaler, egress and payload contract (D26–D29)

This document describes what R1 implements, where it lives, and exactly which bounds
are **declared** today and which are **required-but-unset**. An unset bound is not a
small number: it is an unknown, and every path that would rely on it refuses
(fail closed) instead of falling back to a permissive provider default.

The plan this implements is `benchmarks/evidence/evidence_regeneration_architecture_plan.md`
(§5.6 g, §8.2.5, §10.1, §11.3, D26–D29).

## The two states of a bound

| state | meaning | effect |
|---|---|---|
| **declared** | a concrete value plus the provenance that fixed it (a plan section, an existing published configuration value, or a measured provider reading) | the bound may be used |
| **required-but-unset** | the value is not approved yet | the bound is absent from the deployment, the estimate is *unavailable*, and the dispatch path **refuses** |

`core/r1_bounds.py` is the single place where the bounds live. It never invents a
production value and never hardcodes a price.

## The files

| file | role |
|---|---|
| `core/r1_bounds.py` | the declarations: the three container-class profiles, the egress policies, the payload cap, the pinned model, the manifest check, the fail-closed helpers and the guard |
| `benchmarks/r1_dispatch.py` | the dispatch gate: the single path through which this workflow dispatches a Modal call |
| `benchmarks/r1_estimator.py` | the cumulative cost / egress / storage estimator and its CLI |
| `benchmarks/adapters.py` | the producer, now dispatching only through the gate |
| `modal_app.py` | the deployment: the explicit declarations, the offline GPU class, the producer-enforced payload cap, the dispatch guard |
| `benchmarks/evidence/r1_rate_card.json` | the provider's rates — an approval input with its source and its reading date |
| `benchmarks/evidence/r1_cost_scenario.json` | the **candidate** bounds and per-step quantities of the cost proposal |
| `tests/test_r1_bounds_contract.py` | the proofs (missing bounds block the dispatch, configured bounds are enforced, the cold-container accounting is correct, the storage interval is complete) |

## D26 — explicit request/limit pairs and an explicit lifecycle

| class | cpu | memory | timeout | startup_timeout | scaledown_window |
|---|---|---|---|---|---|
| sandbox CPU | request **2.0** (declared, `core/config.py:37`) / limit **unset** | request **2048 MiB** (declared, `core/config.py:38`) / limit **unset** | **60 s** (declared, `core/config.py:36`) | **unset** | **unset** |
| GPU class (`ProductionAuditAgent`) | request **unset** / limit **unset** | request **unset** / limit **unset** | **1200 s** (declared, the deployed value `modal_app.py`) | **unset** | **unset** |
| persistence function | request **unset** / limit **unset** | request **unset** / limit **unset** | **60 s** (declared, the deployed value) | **unset** | **unset** |

Why the limits are unset: they are production values that change the bill, and the
maintainer has not approved them. A request is not a limit — the provider's default
CPU limit is `request + 16`, which moves whenever the request moves, and the memory
line has **no** limit at all while the limit is unset. The *candidate* values and
their rationale are in `docs/r1_cost_proposal.md`; they are proposals, not
declarations.

`T_billable = startup_timeout + timeout + scaledown_window` is therefore a number
only once all three are declared. The estimator refuses while it is not.

## D27 — the autoscaler policy and the read-back

Every class declares, in its decorator:

| declaration | sandbox CPU | GPU class | persistence function | what it enforces |
|---|---|---|---|---|
| `min_containers` | **0** | **0** | **0** | no container is kept warm while the function is inactive ⇒ every billed container exists to serve a demand |
| `buffer_containers` | **0** | **0** | **0** | no idle container is maintained while the function is active ⇒ no billed container is idle by design |
| `max_containers` | **48** | **32** | **16** | the provider-enforced **concurrency** ceiling of the class — the union ceiling of every authorised step (plan §8.2.5) |
| `scaledown_window` | unset | unset | unset | the idle tail of `T_billable` — an approval input |

`max_containers` is a *concurrency* cap. It never clamps a cumulative quantity: the
number of containers a class starts over a step is bounded by the **invocation
count** (one cold start per invocation is the worst case), not by
`min(invocations, max_containers)`.

**The read-back.** The pinned SDK (1.5.5) has no `Function.autoscaler` namespace, so
the read-back is the **no-argument** call `update_autoscaler()`. Its own docstring
states that "Unspecified parameters will retain their current value, i.e. either the
static value from the function decorator, or an override value from a previous call
to this method" — a call with no argument changes nothing and returns the current
settings. The gate compares the effective `min_containers` / `max_containers` /
`buffer_containers` / `scaledown_window` with the declaration and refuses a
mismatch. **There is no mutating autoscaler call anywhere in the repository** — a
test scans every `.py` file for one.

## D28 — the producer-enforced payload cap and the storage interval

* `MAX_TRAJECTORY_PAYLOAD_BYTES` is **unset**. The persistence function therefore
  refuses *every* payload: it checks the serialised size and raises before it
  writes, so the container is never billed for an oversized write and the volume's
  increment stays bounded by construction.
* The storage interval is a **sum**: `T_store = T_exec + T_post_exec_to_publication +
  T_retention`, and the calendar treatment is `months = 1 + ceil(T_store / 28 days)`.
  The estimator refuses while `T_exec` or the post-execution deadline is undeclared.

## D29 — the egress

| function | class | payload cap | protocol allowance | how the zero/cap is established |
|---|---|---|---|---|
| `verify_exploit_remote` | sandbox CPU | **0** | **unset** | the provider-enforced `block_network` declaration on the exact function (the sandbox functions mount no volume) |
| `verify_replay_remote` | sandbox CPU | **0** | **unset** | the same declaration |
| `record_trajectory_remote` | persistence | **0** | **unset** | 0 external by construction: the function opens a file and commits the volume |
| `ProductionAuditAgent.generate_solidity_exploit` / `.refine_solidity_exploit` | GPU | **0** | **unset** | `local_files_only=True` + the offline environment + the verified cache manifest |
| `prefetch_model_cache_remote` (R2p) | sandbox CPU | **unset** (`pinned_bytes × (1 + R_download)`) | **unset** | the only container that downloads the model |

The GPU class is now **offline**: `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` in
the class environment, `local_files_only=True` on both the tokenizer and the model,
and `@modal.enter()` verifies the volume's cache against the manifest recorded by the
prefetch step — it **fails closed** when the cache does not match, instead of quietly
downloading the model again (a per-container cost of up to 61 GB).

The protocol allowance is added on top of the payload cap for every container of
every class — a payload zero is not a total zero by implication — and it is an
approval input. While it is unset, the egress term of the estimate is unavailable
and the step is not dispatchable.

The pinned revision is declared with its measured byte size:
`qtum/Qwen3-Coder-30B-A3B-Audit` @ `655425b794ae4a19f2ea16fa480c6b39102721ee`,
**61 077 997 602 bytes** (56.888 GiB), measured on 2026-11-11 from the provider's own
file listing.

## The dispatch path

`benchmarks/r1_dispatch.py` is the only path through which this workflow dispatches a
Modal call; `benchmarks/adapters.py` routes all eight of its dispatch sites through
it (a test asserts that no `.remote(` call survives in the producer).

The gate enforces, per step:

1. an **approved step policy** — a provider dispatch without one is refused
   (`no_approved_step_policy`), and the policy itself must declare the wall-clock
   budget, the post-execution deadline, the monetary ceiling and an estimate at or
   below that ceiling;
2. the **completeness of the declared bounds** of the class (`bounds_not_approved`);
3. the **egress declaration** of the function (`no_egress_declaration`,
   `egress_bound_not_approved`);
4. the **ceiling assertion** `cap(c) ≤ max_containers_deployed(c)`
   (`deployed_ceiling_too_low`);
5. the **invocation budget** per class (`invocation_budget_exhausted`);
6. the **concurrency gate** per class (a client-side semaphore);
7. the **producer-enforced payload cap** of the volume-writing functions
   (`payload_byte_cap`);
8. the **autoscaler read-back** before the first container of the class
   (`autoscaler_readback_mismatch`, `autoscaler_readback_unavailable`).

Every refusal is recorded with its machine-readable reason.

**The guard at the function boundary.** Every provider callable of `modal_app.py` is
wrapped in `r1.GuardedRemote`: while a required bound of its container class is
unset, `.remote()` raises `BoundsNotApproved`. A provider callable that is not one
of the declared dispatchable functions is refused as well — the dev T4 agent, the
slither worker and the GRPO trainers are not part of the authorised trace.

**What the guard does not cover.** A manual `modal run` of the app's local
entrypoint drives the GPU class methods directly, and Modal offers no way to revoke
a deployed function's reachability from inside the repository. That path is outside
the repository's control; it is closed by the authorisation of the operator, not by
code.

## What is blocked, and why

| item | state | reason |
|---|---|---|
| the CPU / memory **limits** of the three classes | required-but-unset | production values that change the bill; the maintainer has not approved them (the candidates are in the cost proposal) |
| `startup_timeout`, `scaledown_window` | required-but-unset | approval inputs; `T_billable` is not a number without them |
| the **protocol allowance** | required-but-unset | an approval input with its source and date; without it the egress term is unavailable |
| `MAX_TRAJECTORY_PAYLOAD_BYTES` | required-but-unset | the persistence function therefore refuses every payload (fail closed) |
| the **prefetch function** (R2p) | not implemented in R1 | it is a separately authorised step and its download timeout is an approval input; its per-container egress bound **is** declared, so the estimator can price R2p |
| the **per-stage ceilings** | not approved | they are proposed in `docs/r1_cost_proposal.md` and await the maintainer's review |
| every compute step | **not dispatchable** | the estimate is unavailable while the bounds above are unset, and an unavailable estimate means no dispatch |

Nothing in R1 spends a cent: the declared state is fail-closed, and the guard refuses
every provider call while it holds.
