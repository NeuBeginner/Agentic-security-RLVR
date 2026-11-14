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
| `core/r1_bounds.py` | the declarations: the three container-class profiles, the egress policies, the payload cap, the pinned model, the manifest check, the fail-closed helpers, the refusal registry and the guard (functions **and** classes) |
| `core/r1_approval.py` | the **approval** of a step: the signed artifact, the RSA verification against the pinned public key and the pin of the approval authority — the gate verifies the artifact itself and accepts no "verified approval" object |
| `benchmarks/r1_dispatch.py` | the dispatch gate: the single path through which this workflow dispatches a Modal call, including the read-only autoscaler read-back |
| `benchmarks/r1_estimator.py` | the cumulative cost / egress / storage estimator and its CLI — the one accounting model |
| `benchmarks/adapters.py` | the producer, now dispatching only through the gate |
| `modal_app.py` | the deployment: the explicit declarations, the offline GPU class, the producer-enforced payload cap, the dispatch guard |
| `benchmarks/evidence/r1_rate_card.json` | the provider's rates **and** the free storage allowance — an approval input with its source and its reading date |
| `benchmarks/evidence/r1_cost_scenario.json` | the **candidate** bounds and per-stage quantities of the cost proposal |
| `benchmarks/evidence/r1_call_site_inventory.json` | the **repo-wide inventory** of the provider call sites, with the disposition of each one |
| `benchmarks/evidence/r1_approval_key.json` | the **pinned public key** of the approval authority — `null` in R1, so no approval can be verified and no provider dispatch can be authorised |
| `tests/test_r1_bounds_contract.py` | the proofs of the declarations and of the estimator's arithmetic |
| `tests/test_r1_dispatch_contract.py` | the proofs of the inventory, of the guards, of the read-back, of the network policy and of the invocation budget |
| `tests/test_r1_dispatch_boundary.py` | the boundary proofs: no provider callable in the repository, the class-method boundary, and the gate that is not self-authorising |
| `tests/conftest.py` | the shared fixtures, including the **out-of-band act of the approval authority** (the test key that signs an approval artifact) |
| `tests/test_r1_cost_model.py` | the proofs of the cost model and of the one authoritative command |

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

**The read-back.** The read-back has to answer one question: *are the effective
autoscaler settings of the deployed function the declared ones?* It answers it with
**all four fields** — `min_containers`, `max_containers`, `buffer_containers`,
`scaledown_window` — and it is **fail-closed**: a missing field, a `None` field, a
malformed value and a mismatch are four different refusals, and a partial read is
never accepted.

The pinned SDK (1.5.5) offers **no** non-mutating autoscaler read: the only public
accessor, `Function.update_autoscaler()`, is an *update* RPC
(`FunctionUpdateSchedulingParams`, `modal/_functions.py:1204-1221`). Using it to
verify the autoscaler would change the deployment while verifying it, so **it is not
used** — neither by the gate nor anywhere else in the repository (a test scans every
`.py` file for a *call* of that accessor).

The read-back therefore uses the provider's **read-only** `FunctionGet` RPC — the same
one the SDK itself uses to load a function (`modal/_functions.py:1315-1322`) — and
reads `FunctionData.autoscaler_settings` from its response. The SDK drops that field
when it builds its own `FunctionInfo`, which is why the read happens in
`benchmarks/r1_dispatch.py:provider_autoscaler_reader`. Static inspection against
installed Modal SDK `1.5.5` (`modal/cls.py`, `modal/_functions.py`,
`modal_proto/api_pb2.py`) pins two wire-level requirements in
`provider_autoscaler_reader`:

1. **Class service-function `object_tag` resolution.** A module-level `@app.function`
   is registered in `app._local_state.functions` under its own function name
   (`_tag_ = "verify_exploit_remote"`), whereas `@app.cls` registers a class service
   function under `f"{cls_name}.*"` (`modal/cls.py:730`: `class_service_name = f"{name}.*"`
   and `modal/_functions.py:175`: `self.implementation_name = f"{user_cls.__name__}.*"`).
   `_object_tag("ProductionAuditAgent.generate_solidity_exploit")` therefore resolves
   to `"ProductionAuditAgent.*"` so `FunctionGetRequest.object_tag` addresses the actual
   deployed class service function.
2. **Protobuf `HasField` presence enforcement.** In `modal_proto/api_pb2.py`,
   `FunctionGetResponse.function` (`FunctionData`, field 5),
   `FunctionData.autoscaler_settings` (`AutoscalerSettings`, field 31), and all four
   scalar fields of `AutoscalerSettings` (`min_containers`, `max_containers`,
   `buffer_containers`, `scaledown_window`) declare `has_presence=True`. Because Python
   protobuf returns a default submessage or `0` on `getattr(...)` when an optional
   field is unset — and because `modal/_functions.py:1334` only consumes
   `response.function_id` and `response.handle_metadata` without guaranteeing that the
   server populates `response.function.autoscaler_settings` on `FunctionGet` —
   `provider_autoscaler_reader` explicitly checks `HasField("function")`,
   `HasField("autoscaler_settings")`, and per-field `HasField(name)`. Any unset
   submessage raises `AutoscalerReadbackUnavailable`, and any unset scalar field is
   mapped to `None` (refused with `autoscaler_readback_missing_field`), never silently
   coerced to `0`.

The reader is additionally
**opt-in**: it needs `R1_ENABLE_PROVIDER_READBACK=1` in the environment, so that no
test and no accidental code path can reach the provider. Without the opt-in the read
is *unavailable* and the step is refused (`autoscaler_readback_unavailable`).

The comparison is against the **declaration** of the class
(`core.r1_bounds.declared_autoscaler_settings`). A field that is required-but-unset in
the declaration cannot be compared, so the dispatch is refused
(`autoscaler_readback_malformed`). In the state of this repository that is the case
for `scaledown_window` — which is exactly the intended fail-closed behaviour while
the bound is unapproved.

## D28 — the producer-enforced payload cap and the storage interval

* `MAX_TRAJECTORY_PAYLOAD_BYTES` is **unset**. The persistence function therefore
  refuses *every* payload: it checks the serialised size and raises before it
  writes, so the container is never billed for an oversized write and the volume's
  increment stays bounded by construction.
* The storage interval is a **sum**: `T_store = T_exec + T_post_exec_to_publication +
  T_retention`, and the calendar treatment is `months = 1 + ceil(T_store / 28 days)`.
  The estimator refuses while `T_exec` or the post-execution deadline is undeclared.

### The storage is priced once, on the cycle's footprint

The provider's published allowance of volume storage is **1 TiB per month**
(`modal.com/pricing`: *Volumes $0.09 / GiB / mo **includes 1 TiB / mo free***,
read 2026-11-11). It is an **account-level monthly allowance**, so it is applied
**once** to the cycle — never per stage.

The model has three parts and no fourth:

1. the **direct terms** of a stage — CPU, memory, GPU, egress — are additive over the
   cycle (they do not overlap in time);
2. the **storage** is priced once on the cycle's **time-weighted footprint**
   (`Σ footprint × Δt / 28 days`), the **free allowance** offsets it
   (`1 024 GiB/month × the same month unit`), and the result is **USD 0 while the
   footprint stays inside the allowance**. The footprint itself is reported in every
   run — the **peak** and the **time-weighted average** — and the part above the
   allowance is billed and flagged (`within_free_allowance: false`);
3. the storage cost is then **allocated back** to the stages in proportion to their
   footprint × duration share (the retention interval belongs to the last stage), so
   the sum of the per-stage totals is **exactly** the cycle total: the standing
   baseline is never priced twice.

The current cycle: peak **56.908 GiB**, time-weighted **56.906 GiB**,
**69.58 GiB-month** of footprint against an allowance of **1 252 GiB-month** ⇒ the
storage of the whole cycle costs **USD 0**.00.

### The footprint is a candidate estimate, and the capacity proof is unavailable

The **cost** of the storage above is USD 0 while the footprint stays inside the
allowance — that arithmetic is kept. The **proof** that the cycle fits the account
is a different question, and it is **UNAVAILABLE**:

| what | state | why |
|---|---|---|
| the **baseline** of the remote Volume | **UNKNOWN** | R1 performed **no Volume operation** (it is prohibited in this task), so the existing baseline of this workspace is **not measured** by this evidence. The `0.0 GiB` of the scenario is an **assumption**, not a measurement |
| the **measured local bytes** | **5 034 779 bytes** (0.004689 GiB, 159 tracked files) | the tracked artifacts tree of this repository, measured on 2026-11-12 with `git cat-file -s`. These are the *local* evidence bytes — they are **not** the volume's baseline |
| the **increment of a future run** | **CANDIDATE ESTIMATE** (56.888 GiB of model cache + 0.001/0.02 GiB of evidence) | the size of the artefacts a future run *would* write; the published run's tracked artifacts (0.004689 GiB) anchor the order of magnitude, the values themselves are not measured |
| the **capacity proof** | **UNAVAILABLE** | it needs the volume's existing baseline. It stays unavailable until a **read-only baseline measurement** or a **defensible conservative bound** exists |

The estimator reports these states in every run (`baseline_status`,
`incremental_status`, `capacity_proof`, `capacity_proof_reasons`,
`capacity_proof_missing_evidence`), so a reader never
has to guess whether a number was measured or assumed.

**Exact missing evidence required to close the `< 1 TiB/month` (`1 024 GiB/month`) capacity proof**
(none of which may be collected in R1 because Volume and live provider operations are prohibited):

1. **Pre-R2p read-only baseline of `aegis-model-cache`:** a read-only provider listing of
   existing bytes on Volume `aegis-model-cache` prior to R2p (`baseline_gib`, currently
   assumed `0.0 GiB`).
2. **Account-wide concurrent Modal Volume inventory / bound:** a read-only inventory of
   all other Modal Volumes in the workspace over the same billing month (or an operator
   attestation bounding concurrent non-workflow Volume usage), because Modal's
   `1 TiB/month` (`1 024 GiB/month`) free allowance is an **account-level** monthly
   allowance shared across the entire workspace.
3. **Post-R2p model-cache manifest and Volume footprint read-back:** verification that
   the materialised revision `655425b794ae4a19f2ea16fa480c6b39102721ee` of
   `qtum/Qwen3-Coder-30B-A3B-Audit` on `aegis-model-cache` equals the pinned
   `61 077 997 602 bytes` (`56.888 GiB`) with no residual staging or partial-download
   artefacts.
4. **Post-R3b/R4 trajectory footprint and retention-deletion verification:** measurement
   of the written trajectory bytes after R3b and R4 (confirming they remain within the
   `0.021 GiB` candidate bound) and verification of their deletion at the end of the
   30-day retention window.

## D29 — the egress

| function | class | payload cap | protocol allowance | how the zero/cap is established |
|---|---|---|---|---|
| `verify_exploit_remote` | sandbox CPU | **0** | **unset** | the provider-enforced `block_network` declaration on the exact function (the sandbox functions mount no volume) |
| `verify_replay_remote` | sandbox CPU | **0** | **unset** | the same declaration |
| `record_trajectory_remote` | persistence | **0** | **unset** | 0 external by construction: the function opens a file and commits the volume |
| `ProductionAuditAgent.generate_solidity_exploit` / `.refine_solidity_exploit` | GPU | **0** | **unset** | the **provider-enforced `block_network` of the whole GPU class** (see below) + the offline environment + the verified cache manifest |
| `ProductionAuditAgent.audit_target_contract` | GPU | **0** | **unset** | the same class-level declaration; the call site itself is refused (it is not one of the authorised stages) |
| `prefetch_model_cache_remote` (R2p) | sandbox CPU | **0** | **unset** | the outbound payload is zero by construction: the model is **downloaded** (that is ingress — see below) and written to the volume (a volume write is not egress) |

### The ingress is declared separately from the egress

The provider bills **outbound** traffic as egress. A download *into* the container is
**ingress** and is not billed at the egress rate, and a read or a write of a Modal
Volume is not egress either
(<https://modal.com/docs/guide/network-egress-billing>, read 2026-11-12).

The model download of R2p is therefore **not** an egress: it is declared as an
**ingress cap** (`core.r1_bounds.INGRESS_POLICIES`), bounded by
`pinned_bytes × (1 + R_download)` = **122 155 995 204 bytes** with `R_download = 1`.
The estimator prices the inbound bytes at the **ingress rate** of the rate card
(`ingress_per_gib = 0.0`), never at the egress rate. The *outbound* traffic of the
prefetch stays in the egress term: the protocol allowance (1 MiB per container, the
measured order of magnitude of the control-plane and volume data-path traffic).

The two are never mixed: an ingress declaration belongs to one dispatched function,
so a step that dispatches a function with an ingress declaration has to declare that
declaration — otherwise the step is **unavailable** (fail closed), not silently
counted as zero.

### The GPU class: provider-level blocking

The GPU class declares `block_network=r1.class_network_policy(r1.GPU_CLASS)`, which is
**True**. The semantics are proven by the SDK itself: the parameter exists for
`app.cls` (`modal/app.py:1102`), is forwarded at `modal/app.py:1288` into
`_Function._from_local` for the class service function `ProductionAuditAgent.*`, and is
transmitted to the provider as `api_pb2.Function.block_network`
(`modal/_functions.py:1044`) — the provider's documented outbound-traffic switch.
Static inspection of `modal_app.app._local_state.functions["ProductionAuditAgent.*"]`
confirms the exact closure state formed by `modal_app.py`:

* `_tag_ == "ProductionAuditAgent.*"`
* `block_network is True`
* `gpu == "H100"`, `timeout == 1200`, `min_containers == 0`, `buffer_containers == 0`, `max_containers == 32`
* `cpu is None`, `memory is None`, `scaledown_window is None` (unapproved bounds remain absent from `r1.GPU_PROFILE.modal_kwargs()`, never replaced by permissive defaults; `modal/app.py:1282` internally sets `startup_timeout = startup_timeout or timeout` on `_Function`, while `r1.GPU_PROFILE.startup_timeout_sec` remains `Unset` so the R1 gate blocks dispatch)
* `/vol/models` is mounted to the `aegis-model-cache` Volume (`validated_volumes_no_cloud_buckets`), and `secrets` includes `r1.OFFLINE_ENV` (`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`).

The declaration is **not** a workload-level
convention: the offline environment and the verified cache manifest are the second,
independent layer.

The class-level policy covers **all** the methods of the class — the blocking is a
property of the class — so a method that is not part of the authorised trace inherits
it as well; it is refused at the call boundary instead.

**The one open item.** Modal's documentation does not state whether a *volume mount*
survives `block_network=True`. The SDK does not validate the combination either
(`modal/_functions.py`, `modal/app.py` and the mount helpers were checked: no
client-side rule). The failure mode is **fail-closed** — a container that cannot read
the model cache raises and the dispatch fails; it can never leak egress. But the
compatibility has to be confirmed before R3b/R4 are dispatched. If the mount turns out
to be incompatible, the alternative branch of the plan applies: a conservative,
evidence-backed **non-zero** payload cap for the GPU class — and that cap is priced in
the estimate (see `docs/r1_cost_proposal.md`, "the sensitivity of the egress bound").

The GPU class is offline in three independent ways: `block_network=True` on the class,
`HF_HUB_OFFLINE=1` / `TRANSFORMERS_OFFLINE=1` in the class environment,
`local_files_only=True` on both the tokenizer and the model, and `@modal.enter()`
verifies the volume's cache against the manifest recorded by the prefetch step — it
**fails closed** when the cache does not match, instead of quietly downloading the
model again (a per-container cost of up to 61 GB).

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

**The inventory.** `benchmarks/evidence/r1_call_site_inventory.json` lists **every**
provider call site of the repository — 20 call sites, grouped into 16 call chains —
with the disposition of each one.
`tests/test_r1_dispatch_contract.py` parses every `.py` file of the repository, finds
every call chain that reaches a provider's `remote` and compares the result with the
inventory: a new call site that is not classified fails the test, so the inventory
cannot silently go stale. The dispositions are

| disposition | meaning |
|---|---|
| `gated` | an authorised function; the object is a `GuardedRemote` and the guard routes the call through the single gate |
| `refused` | not part of the authorised trace; the guard refuses the call site with the reason of the refusal registry |
| `guarded_class_method` | a class method; the class guard resolves the call site at runtime — authorised for the GPU class, refused for the T4 dev agent |
| `gate` | the gate itself: the only place in the repository that calls a provider's `remote` |

There is **no** "declared out of scope" disposition: a provider call that is not gated
is **refused**, with the reason of the refusal registry. The Iteration 19 runtime smoke
app was classified that way, and the R1 review named it as an unguarded invocation —
a separate, CPU-only deployment is still an unauthorised remote workload. Its live
invocation is now refused before the ephemeral app starts and before the provider's
entry point is touched (`benchmarks/run_iteration19_cpu_smoke.py::_assert_authorised`);
only an explicit maintainer approval (`R1_APPROVE_ITERATION19_CPU_SMOKE=1`) lifts the
refusal, and the historical Iteration 19 evidence is untouched by any of this.

The gate enforces, per step:

1. the **authorisation of the call site and its authoritative container class**
   (`unauthorised_call_site`) — the refusal registry of `core/r1_bounds.py` names
   every provider call site that is *not* part of the authorised trace: the T4 dev
   agent, the Slither worker, the fault-injection worker, the volume audit, the GRPO
   diagnostic and the GRPO training, and the audit-role method of the GPU class. The
   gate also checks that the caller-supplied `container_class` equals the
   authoritative class mapped in `core/r1_bounds.FUNCTION_CLASS`, so a call site
   cannot be mislabelled to borrow another class's bounds or allowance. The check is
   the **first** one, so a refusal names the call site instead of a downstream
   symptom;
2. an **approved step policy** — a provider dispatch without one is refused
   (`no_approved_step_policy`), and the policy itself must declare the wall-clock
   budget, the post-execution deadline, the monetary ceiling and an estimate at or
   below that ceiling;
3. a **signed approval of both the `StepPolicy` and the complete D26–D29 dispatch
   envelope** (`approval_not_verified`, `approval_policy_mismatch`,
   `call_site_not_approved`, `approval_envelope_unavailable`,
   `approval_envelope_mismatch`) — the gate verifies the artifact itself at the gate
   and again immediately before provider entry; see *The approval is external* below;
4. the **completeness of the declared bounds** of the class (`bounds_not_approved`);
5. the **egress declaration** of the function (`no_egress_declaration`,
   `egress_bound_not_approved`);
6. the **ceiling assertion** `cap(c) ≤ max_containers_deployed(c)`
   (`deployed_ceiling_too_low`);
7. the **producer-enforced payload cap** of the volume-writing functions
   (`payload_byte_cap`);
8. the **autoscaler read-back** before the first container of the class
   (`autoscaler_readback_unavailable`, `autoscaler_readback_missing_field`,
   `autoscaler_readback_malformed`, `autoscaler_readback_mismatch`);
9. the **concurrency gate** per class (a client-side semaphore;
   `concurrency_gate_timeout`);
10. the **invocation budget** per class (`invocation_budget_exhausted`).

Every refusal is recorded with its machine-readable reason.

**The approval is external — and binds the complete D26–D29 dispatch envelope, not
`StepPolicy` alone.** The gate is a mechanism, not an authorisation: a step policy
that a caller constructs in-process — with an `approved_by` of its own choosing —
authorises nothing. The contract distinguishes two levels:

* **(a) Signature verification of `StepPolicy` alone (`policy_digest`)** binds only the
  per-step invocation budgets, concurrency caps, wall-clock and post-execution
  deadlines, estimate and monetary ceiling. That check is necessary (`approval_policy_mismatch`),
  but by itself it is **insufficient**, because resource profiles, autoscaler lifetimes,
  network/egress policies, persistence caps, model/cache identities and cost inputs live
  outside `StepPolicy`. A policy-only artifact is therefore rejected outright
  (`approval_not_verified`).
* **(b) Approval of the complete D26–D29 dispatch envelope (`dispatch_envelope_digest`)**
  is required before any stage could become dispatchable. The signed JSON artifact must
  include a canonical `dispatch_envelope` (`schema: "r1-dispatch-envelope/1"`) binding
  every effective input that can alter the safety, resource or cost envelope: the
  `StepPolicy`, the deployment and volume configuration (including `/vol/models` mount
  path and free-allowance parameters), the `solc`/`foundry` toolchain versions, the
  authoritative `function_class_map`, both declared (`core.r1_bounds.PROFILES`) and
  effective per-class `ResourceProfile`s (CPU/memory request/limit, GPU type,
  startup/execution/scaledown lifetimes, min/buffer/max containers, volume mounts and
  provenance), declared and effective egress/ingress/network-blocking policies,
  `MAX_TRAJECTORY_PAYLOAD_BYTES`, `PINNED_MODEL` (enforced via `revision=` in
  `modal_app.py` and SHA-256 checks in `verify_model_cache_manifest`), the live
  model-cache manifest state and SHA-256 digest, and the SHA-256 digests of
  `benchmarks/evidence/r1_cost_scenario.json` and `benchmarks/evidence/r1_rate_card.json`.

The gate recomputes `dispatch_envelope_payload()` from the live authoritative
declarations and the gate's effective configuration (including any caller-injected
`profiles` or `egress_policies`) at dispatch time — and re-verifies it immediately
before provider entry — comparing its canonical SHA-256 digest against the signed
`claims.dispatch_envelope_digest`. Any missing, extra, non-finite, malformed or altered
bound, profile, network policy, model/cache identity or cost-input byte fails closed
with `approval_envelope_unavailable` or `approval_envelope_mismatch` before any
provider call is made. The RSA signature (RSASSA-PKCS1-v1_5 over SHA-256) is verified
against the **public** key of the approval authority pinned in
`core/r1_approval.py::PINNED_PUBLIC_KEY` and mirrored in
`benchmarks/evidence/r1_approval_key.json`; the private half never enters this
repository or process.

**The gate verifies the artifact itself.** The dispatch gate takes the **signed
artifact** — the payload and its signature — and verifies the signature itself, at
dispatch time, against the pinned key. It accepts **no** "verified approval" object:
there is no value whose *construction* conveys authority, so there is nothing for a
caller to forge. The R1 re-review named the previous design as a P0: the approval
class carried a module-global issuance token that any caller could read and hand to
the constructor, and a forged approval reached the provider. The token is gone, and
the boundary is the signature.

**The pin lives in the source, not in a file that is read at runtime.** A caller that
can write a file into the working tree must not be able to install a key of its own.
The evidence mirror is a second copy of the pin: a mirror that is missing, malformed
or different from the source pin is refused, and with it every approval (fail
closed).

**R1 pins no key** — the source pin is `null` and the mirror says `null` too,
because no step of the evidence-regeneration workflow has been approved by the
maintainer yet. The consequence is the intended one: **no provider dispatch is
possible in R1**, and it is impossible *structurally* — not only because the bounds
of the container classes are required-but-unset. The approval binds the exact policy
it approves: a caller that swaps a cap, a budget or a ceiling after the approval was
issued does not hold the approval any more (`approval_policy_mismatch`), and an
approval of another step does not cover this one (`call_site_not_approved`).

The invocation allowance is consumed only by a dispatch that really starts a
container.** The check and the increment happen under **one** lock, so two concurrent
dispatches can never both pass the same remaining allowance; and the allowance is
consumed **after** every other gate, immediately before the call. A refused attempt —
the authorisation, the policy, the approval, the bounds, the egress, the ceiling, the
payload cap, the **concurrency gate**, the read-back or the budget itself — starts no
container, so it consumes nothing. The policy of the concurrency-refused attempt is
therefore explicit: **it costs no invocation**, and the allowance stays intact for the
next attempt (a test pins it).

**The guard at the function boundary.** Every provider callable of `modal_app.py` is
guarded: the module-level functions in `r1.GuardedRemote`, the Modal **classes** in
`r1.GuardedClass` (whose instances return `r1.GuardedClassMethod` objects). The class
methods were the bypass the review named: before, the module-level guard covered only
`modal.Function` objects, so `ProductionAuditAgent().generate_solidity_exploit.remote(...)`
reached the provider without the gate. Now:

* a call site that is not part of the authorised trace is refused with the reason of
  the refusal registry (`UnauthorisedCallSite`);
* while a required bound of the class is unset, `.remote()` raises
  `BoundsNotApproved`;
* an authorised call is routed through the **same** gate as every other dispatch, so
  the budget, the concurrency gate, the ceiling, the payload cap and the read-back
  apply to it;
* the mutating `update_autoscaler` accessor is **unreachable** through the guard.

**The guard holds no provider object.** The R1 re-review named a second bypass: the
wrappers kept the raw Modal objects in their own instance dictionaries (`_fn`, `_obj`,
`_cls`), so a caller could reach the raw provider callable and call it without the
gate. That is closed on three levels:

1. **no attribute yields a raw provider callable.** The raw objects live in the
   module-private registry of `core/r1_bounds.py`; the guard objects hold only an
   opaque token and the call-site name, and every underscore-prefixed attribute is
   refused outright instead of being delegated to the raw object;
2. **the guard is installed on the provider object itself** (`r1.GuardedProviderRemote`
   replaces the object's own `remote`). Every reference to that object — the
   module-level name, an import of it, the object in the registry — reaches the gate,
   not the provider. The installation fails closed if it cannot be made;
3. **no provider entry point is captured or stored.** The entry point the provider
   answers on is *not* kept: it stays in the provider object's own class and is
   resolved from there at the moment of the call
   (`core.r1_bounds._call_provider_entry_point`). The repository therefore holds **no
   provider callable at all** — not in a closure, not in a registry, not in an
   attribute of a guard. The resolver is private, it returns the *result* of the call
   and never the callable, and it refuses to run outside the gate's dispatch method
   (the check is against the **code object** of that method).

**The class methods are guarded at their production boundary.** The provider SDK
produces a **fresh** provider method on every attribute access of a class instance
(`modal/cls.py:442`), so a guard that covers only the method it handed out leaves the
next access unguarded — the bypass the re-review named: the raw class instance was
reachable through the module's private registry, and the provider method resolved
from it had an **unguarded** `remote`. The guard is therefore installed where the
method is *produced*: the instance is moved to a subclass of its class whose
attribute resolution hands out the guard (`core.r1_bounds._guarded_class_getattr`),
so `getattr(raw_instance, "generate_solidity_exploit")` yields a
`GuardedClassMethod` — for every method of the class, and for every access. The
SDK's own resolver stays in the SDK's class: the guard reaches it through `super()`
and never keeps a copy of it, so there is no registry and no closure through which
the unguarded resolution could be reached.

**The threat model is explicit.** Python has no private memory, so a caller that
deliberately reads the module's underscore-prefixed registries can still reach a
*provider object* — and an adversary who can execute arbitrary code in the same
process can patch the guard, the registries, the verifier or the gate itself, and
can reach the provider SDK through the SDK's own internals (the async original of a
function, the application's function registry, the class-descriptor protocol). That
is a property of the language and of the process, not of this guard. What the guard
*does* guarantee is the property the evidence needs, and it is auditable:

* **every provider entry point this repository hands out is gated** — the module-level
  names, the imports, the objects in the registries, the guards and the guarded
  class instances;
* **no provider callable is held anywhere in the repository** — not in a closure, not
  in a registry, not in an attribute (a test invokes every callable the module holds,
  including the contents of their closures, against a fake provider and requires zero
  recorded calls);
* **no provider dispatch is possible without a signed approval of the complete
  D26–D29 dispatch envelope** — the gate verifies the artifact itself against the
  pinned key and compares both `policy_digest` and the live `dispatch_envelope_digest`
  (covering resource profiles, autoscaler lifetimes, network/egress/ingress bounds,
  payload caps, volume/toolchain settings, pinned model/cache digests and cost/rate-card
  SHA-256 digests). R1 pins no approval key, so no live provider dispatch is possible at
  all;
* **no value whose construction conveys authority exists** — there is no issuance
  token, no unforgeable-in-practice marker and no "verified approval" object the
  gate accepts; the only way through the boundary is a signature of the approval
  authority.

**What the guard does not cover.** A manual `modal run` of the app's local entrypoint
drives the GPU class methods directly, and Modal offers no way to revoke a deployed
function's reachability from inside the repository. Inside the repository the path is
now closed (the class guard refuses it); what remains outside the repository's control
is an operator invoking an **already deployed** app, and that is closed by the
authorisation of the operator, not by code.

## What is blocked, and why

| item | state | reason |
|---|---|---|
| the CPU / memory **limits** of the three classes | required-but-unset | production values that change the bill; the maintainer has not approved them (the candidates are in the cost proposal) |
| `startup_timeout`, `scaledown_window` | required-but-unset | approval inputs; `T_billable` is not a number without them |
| the **protocol allowance** | required-but-unset | an approval input with its source and date; without it the egress term is unavailable |
| `MAX_TRAJECTORY_PAYLOAD_BYTES` | required-but-unset | the persistence function therefore refuses every payload (fail closed) |
| the **prefetch function** (R2p) | not implemented in R1 | it is a separately authorised step and its download timeout is an approval input; its per-container **ingress** bound **is** declared, so the estimator can price R2p |
| the **Iteration 19 CPU smoke** (a separate deployment) | **refused** | it is not part of the authorised trace: no approved step policy, no declared bounds, no egress declaration. The live invocation refuses before the ephemeral app starts; only an explicit maintainer approval lifts it |
| the **capacity proof** of the storage | **unavailable** | the baseline of the remote Volume is not measured by this evidence (no Volume operation); it needs a read-only baseline measurement or a defensible conservative bound |
| the **per-stage ceilings** | not approved | they are proposed in `docs/r1_cost_proposal.md` and await the maintainer's review |
| every compute step | **not dispatchable** | the estimate is unavailable while the bounds above are unset, and an unavailable estimate means no dispatch |
| every **provider dispatch** of R1 | **refused** | no step of the workflow is approved: the repository pins no approval key, so no approval artifact can be verified and the gate refuses with `approval_not_verified` — the refusal is structural, not a side effect of the unset bounds |

Nothing in R1 spends a cent: the declared state is fail-closed, the approval of every
step is absent, and the guard refuses every provider call while it holds.
