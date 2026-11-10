# Consolidated Closure — Change Impact Matrix

**Closure:** consolidated architecture closure of PR #12 (after Iteration 23)
**Scope:** the whole chain — `Modal producer / client provider → stage response capture → evidence artifacts → strict provenance validator → billing join → adapter & target manifests → evaluator → final report` — with **two** confirmed defects (one **P0**, one **P1**) and one full-chain audit.
**Trigger:** independent review comment [`issuecomment-6768215450`](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/12#issuecomment-6768215450) (2026-11-10).
**Rule of this document:** it is written **before** any code change and is committed **before** the code it describes.

**Authorization / boundaries (unchanged from the review):**

| allowed | forbidden |
| --- | --- |
| the shared evidence contract `benchmarks/evidence_integrity.py` | any live Modal invocation or provider query |
| the evaluator `benchmarks/evaluator.py` and the report path of `benchmarks/benchmark_runner.py` | any deployment, redeployment, worker restart or modification of a live worker |
| a new consolidated validator, a new focused test suite, the validation evidence bound to its own code SHA | any GPU (H100 / T4 / any other), any paid compute |
| running the focused suites, the Iterations 14–23 suites, the full regression, the Foundry integration and CI | merging PR #12, rebasing a shared branch, touching `main`, PR #8 or the integration branch |
| re-reading the artifacts of Iterations 14–23 from disk | weakening a validator, a compatibility path or a test to make a report green |

**Stop condition.** If closing a defect would require a live provider call, a deployment or paid compute, the closure stops at that point and reports the blocker instead of lowering a bar.

---

## 1. Why this closure exists

Iteration 23 was **accepted for its narrow scope**. It is **not** an acceptance of PR #12, and the review is explicit about it:

> Do not start another one-field patch. Treat this as one consolidated closure task. First update a single Change Impact Matrix covering the full chain.

Two defects are confirmed and must be closed in **this** task:

* **P0 — the fail-closed evaluator leak.** A target that did **not** complete is serialized as a **negative finding** (`detected: false`) instead of "no finding at all" (`null`). This contradicts the contract of the module that states it.
* **P1 — the run-level observation-side gap.** The strict consumer side-checks the **stage** facts of an invocation, but the **run-level** application id `modal_invocation_provenance.modal_app_id` is checked only in its `NOT_AVAILABLE` shape. An `OBSERVED` run-level application id is not side-checked at all — the gap that Iteration 23 recorded as a known limitation and deliberately did not close.

Beyond the two defects the review requires a **full-chain audit** (§3) and the reconciliation of the report semantics (§8) — the report has to keep *planned / attempted / executed / observed / reported* apart, and *unavailable / failed / unknown / not-run* distinguishable, in **every** output.

---

## 2. The two confirmed defects, exactly as they stand

### 2.1 P0 — the fail-closed evaluator leak

**The line** — `benchmarks/evaluator.py`, `evaluate_baseline_run()`, per-target detail construction:

```python
det = False if (is_compile_err or a.security_verdict in ("RUNTIME_REVERT", "GENERATION_FORMAT_ERROR", "SAFE_RUN")) \
      else (a.detected if a.status == ExecutionStatus.SUCCESS else None)
```

The guard on the execution status sits in the **else** branch. The verdict branch wins first, so a run that **failed** is still turned into `False` — a negative finding — whenever its verdict is one of the four listed values.

| # | status | `security_verdict` | today | fail-closed contract |
| --- | --- | --- | --- | --- |
| 1 | `FAILED` | `COMPILATION_ERROR` | `false` ❌ | `null` |
| 2 | `FAILED` | `RUNTIME_REVERT` | `false` ❌ | `null` |
| 3 | `UNAVAILABLE` | `COMPILATION_ERROR` | `false` ❌ | `null` |
| 4 | `UNAVAILABLE` | `SAFE_RUN` | `false` ❌ | `null` |
| 5 | `FAILED` | `EXECUTION_FAILURE` | `null` ✅ | `null` |
| 6 | `SUCCESS` | `COMPILATION_ERROR` | `false` ✅ | `false` |
| 7 | `SUCCESS` | (none) | `a.detected` ✅ | `a.detected` |
| 8 | `SUCCESS` | `INFRA_ERROR` | `false` ❌ (found by the audit, §3.1 F4) | `null` |
| 9 | `SUCCESS` | `CHEATCODE_DETECTED` | `false` ✅ but not in the set of the verdicts that may never count as a positive breach (§3.1 F5) | `false` |


The contract of the module itself (`benchmarks/evaluator.py`, module docstring) says:

> Incomplete/failed runs are NEVER treated as negative detections (detected=False).

The same module therefore contradicts its own contract. The existing test `tests/test_real_benchmark_execution.py::test_compilation_failure_never_counted_as_exploit_or_breach` **encodes the defect** (row 1): it asserts `detail["detected"] is False` for a `FAILED` artifact. Its *intent* — a compilation failure is never a positive finding — is preserved and strengthened by the fix; the assertion itself has to change.

**The same value reaches the report through a second door.** `BaselineEvaluationResult.target_artifacts` is a serialization of the same artifacts (`benchmarks/protocol.py::TargetExecutionArtifact.to_dict`), and `detected` there is the dataclass **default** `False` for every artifact the adapters built without a finding. A reader of `benchmark_results.json` / `summary.json` / `latest_summary.json` therefore sees `status: FAILED` next to `detected: false` in `target_artifacts[]` as well.

**What is *not* broken.** The scoring loop of `evaluate_baseline_run()` (the confusion matrix) runs **only** when every artifact is `SUCCESS`, so no metric is computed from a failed run; the fail-closed metrics (`precision`, `recall`, `f1`, TP/FP/TN/FN) are `None` for a mixed run. The defect is in the **serialized per-target view**, not in the metric computation.

### 2.2 P1 — the run-level observation-side gap

**The registry** — `benchmarks/evidence_integrity.py`, `PROVIDER_OBSERVATION_SOURCES`:

| field | registered source | registered side | shape |
| --- | --- | --- | --- |
| `function_call_id` | `modal.current_function_call_id()` | **worker** | `fc-…` |
| `app_id` | the provider-issued `App.app_id` of the running app | **client** | `ap-…` |
| `app_page_url` | `App.get_dashboard_url()` | **client** | `https://modal.com/id/ap-…` |
| `container_id` | the provider's call graph + container listing | **client** | `ta-…` |

**The producer** — the run-level application id is the application id of the **EVM sandbox stage** of the same invocation: `benchmarks/adapters.py:2366` (`"modal_app_id": _stage_facts("evm_sandbox")["app_id"]`) and `benchmarks/run_iteration21_producer_capture.py:307`. It is therefore either the `NOT_AVAILABLE` fact of the stage (the worker cannot read the app id — `modal_app.py::capture_modal_runtime_identity`) or an `OBSERVED` fact.

**The consumer** — `validate_modal_invocation_provenance(..., strict_sources=True)`:

* the **stage** facts go through the strict loop (Iteration 22 + 23): the side has to be present, known and **exactly the registered** one;
* the **run-level** `modal_app_id` is only checked in its `NOT_AVAILABLE` shape (the evidence reference has to be the one of the EVM sandbox stage). It is **never** passed through `validate_provider_observation_source()`.

**The hole.** A run-level application id that is `OBSERVED` but

* names **no** side, or a `null` side, or an **unknown** side,
* names the **worker** side although the registered side of `app_id` is the **client** side,
* carries a **legacy flat** value (a bare string) that names no side at all,
* or is **missing** altogether,

is accepted by the strict consumer today. Only the *stage* copy of the same field is side-checked — so the strict mode accepts two contradictory statements about the same application id in one artifact: the stage copy may say "client observed it" while the run-level copy says nothing at all, or says "worker observed it".

**Compatibility.** The artifacts of Iterations 14–20 carry the flat, side-less shape and are read through the **non-strict** path. The strict mode is the new, stricter contract; the compatibility path stays exactly as it is and no side is ever inferred or backfilled.

---

## 3. The full chain under audit

The audit covers every link of the chain. For each field/state the audit has to prove: **producer source → allowed type/status → observation side → correlation key → evidence artifact → validator → serializer → downstream consumer**.

| # | link | producer | evidence artifact | validator | serializer | consumer | defect found |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Modal producer | `modal_app.py::capture_modal_runtime_identity` | the stage response artifact | `validate_runtime_identity_envelope` | the envelope of the capture | `build_stage_identity_facts` | — |
| 2 | client provider lookup / correlation | the client block (`client_observed`) | the client block of the artifact | `validate_client_observed_facts`, `validate_client_container_correlation` | `modal_invocation_provenance.client_observed` | the strict consumer, the billing join | — |
| 3 | stage response capture | `StageResponseCapture` | `write_stage_evidence_artifact` | `validate_stage_capture`, `validate_stage_evidence_artifact` | the stage evidence JSON | the provenance block | — |
| 4 | strict provenance validator | the producer + the adapters | the stage evidence JSON | `validate_modal_invocation_provenance` | — | the report, the billing join | **P1** |
| 5 | billing join | `benchmarks/regenerate_billing_join_table.py` | `benchmarks/evidence/modal_billing_join_table.json` | `resolve_billing_join`, `validate_billing_attribution`, `cross_check_app_ids` | the join table | the provenance validator | — |
| 6 | adapter / target manifests | `benchmarks/benchmark_runner.py` (`AdapterRunManifest`, `per_target_provenance`) | the per-target artifact JSON | `verify_manifest_git_integrity` | `reproducibility_manifest.json` | the report | **P0** (the per-target record of a failed run) |
| 7 | evaluator | `benchmarks/adapters.py` → `TargetExecutionArtifact` | — | `evaluate_baseline_run` | `details[]`, `target_artifacts[]` | the report | **P0** |
| 8 | final report | `benchmarks/benchmark_runner.py` | — | — | `benchmark_results.json`, `summary.json`, `latest_summary.json` | a reader of the report | **P0** |

The audit of the states (execution status, `security_verdict`, `orchestration_status`, `generation_outcome`, `evm_outcome`, `replay_status`, `persistence_status`, `detected`) is the table of §8.

### 3.1 The findings of the audit — every one of them, and what happened to it

The audit was executed over the whole chain, field by field, with the producer source, the allowed type/status, the observation side, the correlation key, the evidence artifact, the validator, the serializer and the downstream consumer of every state.

| # | finding | where | status |
| --- | --- | --- | --- |
| F1 | the run-level application id of an **observed** fact is not side-checked by the strict consumer | `benchmarks/evidence_integrity.py`, the strict branch of `validate_modal_invocation_provenance` | **closed by this closure (P1)** |
| F2 | a failed or unavailable target is serialized as a **negative finding** (`detected: false`) | `benchmarks/evaluator.py`, the per-target detail | **closed by this closure (P0)** |
| F3 | the same target is serialized a second time as `detected: false` in `target_artifacts[]` — the same run appeared in one report in two incompatible ways | `benchmarks/protocol.py::TargetExecutionArtifact.to_dict` via the evaluator | **closed by this closure (P0)** |
| F4 | a completed execution whose verdict says that the **audit itself** failed (`INFRA_ERROR`) is serialized as a negative finding | the verdict reaches `security_verdict` through `benchmarks/adapters.py` | **closed by this closure (P0, extended)** — see §4.1 |
| F5 | a rejected cheatcode attempt is not in the set of verdicts that may never count as a positive breach | `benchmarks/evaluator.py` vs `core/evaluator.py`, which already treats it as a rejected candidate | **closed by this closure (P0, extended)** — see §4.1 |
| F6 | the strict mode is not reachable from the public wrapper: `benchmarks/protocol.py` does not pass `strict_sources`, and the benchmark run validates **no** provenance at all | `benchmarks/protocol.py`, `benchmarks/benchmark_runner.py` | **documented, not changed** — the strict mode is the contract of the evidence chain of Iterations 21–23; the production run has no live artifacts to validate it against, and closing it would require a live invocation |
| F7 | the registry `MODAL_PROVENANCE_STAGES` is dead, the name of a stage is never checked and the four canonical stages are not mandatory | `benchmarks/evidence_integrity.py` | **documented, not changed** — a stage-name rule would refuse artifacts that the published evidence of Iterations 16–23 contains; it is a separate, wider contract |
| F8 | two vocabularies of `persistence_status` (`not_eligible` / `NOT_ELIGIBLE`) and no validator for either | `benchmarks/adapters.py`, `benchmarks/benchmark_runner.py` | **documented, not changed** — a vocabulary change would rewrite the manifests of the historical run |
| F9 | `orchestration_status` is always `COMPLETED`, also on the failed paths | `benchmarks/adapters.py` | **documented, not changed** — the producer is not the defect of this closure and its source stays byte-wise unchanged |
| F10 | the CPU-smoke producer publishes a container id from `MODAL_WORKER_ID`/`HOSTNAME` — a source that is not in the registry | `benchmarks/modal_cpu_smoke_app.py` | **documented, not changed** — the CPU-smoke evidence of Iteration 19 is a separate capture and stays as it is |
| F11 | the billing join correlates on the function-call id only and stays 100 % `UNATTRIBUTED`; the raw billing export carries no correlation column | `benchmarks/regenerate_billing_join_table.py`, `benchmarks/evidence/modal_billing_join_table.json` | **documented, not changed** — it is the state of the historical evidence, and the reviewer requires it to stay visibly failed |
| F12 | the manifest and the join table carry no `detected` and no execution status of the target | `benchmarks/benchmark_runner.py`, `benchmarks/regenerate_billing_join_table.py` | **documented, not changed** — they carry `security_verdict`, `replay_status` and `persistence_status`; adding the detection state to the manifest would change the manifest format of the historical run |

**No finding was closed by weakening a validator, a compatibility path or a test.**


---

## 4. Design

### 4.1 Rule P0 — the fail-closed detection

> A **negative detection** exists only for a **successfully completed, semantically valid** execution. A run that did not complete — `FAILED`, `UNAVAILABLE` — has **no** finding: its detection is `null`, never `false`.

The audit of the chain found **two** more cases of the same class, and they are closed in the same rule:

* a completed execution whose verdict is `INFRA_ERROR` — "harness / environment / toolchain failure" (`core/schemas.py`) — did **not** validly conclude about the target, so it is not a negative finding either. The training path excludes the very same category from the group statistics for the very same reason (`tests/test_grpo_integrity.py`);
* a rejected cheatcode attempt (`CHEATCODE_DETECTED`) is an **audit-level** outcome — the candidate was invalid, the exploit did not work — and joins the set of the verdicts that may never count as a positive breach, exactly like the compilation error and the runtime revert.

Implementation in `benchmarks/evaluator.py`:

| # | place | change |
| --- | --- | --- |
| 1 | a new resolver `resolve_detection(artifact)` | returns `(detection, detection_state)`: `None` / `NOT_EVALUATED` for a non-`SUCCESS` execution and for a completed execution with an **invalid** verdict (`INFRA_ERROR`); `False` / `NEGATIVE` for a `SUCCESS` execution with one of the negative verdicts (`COMPILATION_ERROR`, `RUNTIME_REVERT`, `GENERATION_FORMAT_ERROR`, `SAFE_RUN`, `CHEATCODE_DETECTED`); `bool(artifact.detected)` / `POSITIVE` or `NEGATIVE` otherwise |
| 2 | the per-target `details[]` row | `detected` comes from the resolver; the new `detection_state` names the state explicitly; the breach counters of a run without a finding are `0` (a run that did not conclude cannot have verified a breach) |
| 3 | the per-target `target_artifacts[]` record of the report | the same resolver is applied, so a failed/unavailable record carries `detected: null` and `detection_state: NOT_EVALUATED`; the producer's raw claim is preserved under `producer_detected`, `producer_verified_breaches` and `producer_replayed_breaches` — nothing is lost, and the hashed artifact file on disk stays untouched |
| 4 | the fail-closed gate of the baseline | a target **without** a valid evaluation makes the baseline non-scorable: the status is `INCOMPLETE` and every metric stays `None` — the same rule that already applies to a failed or unavailable target |
| 5 | the confusion matrix | it reads the **same** resolver, so the report and the metrics can never disagree |

**The state vocabulary of the report** becomes explicit:

| `detection_state` | meaning | `detected` |
| --- | --- | --- |
| `POSITIVE` | the execution completed and found a vulnerability | `true` |
| `NEGATIVE` | the execution completed and found nothing | `false` |
| `NOT_EVALUATED` | the execution did **not** produce a valid conclusion — there is no finding | `null` |


### 4.2 Rule P1 — the run-level side check

> In the strict mode the run-level application id is a **typed fact** of the same registry as the stage facts: an `OBSERVED` value has to name the **registered** side of the field (`client`), a legacy flat value names no side and is refused, and a run that records no application id at all is refused.

Implementation in `benchmarks/evidence_integrity.py` — one additive branch in the strict mode of `validate_modal_invocation_provenance()`:

| # | case | strict mode | compatibility path |
| --- | --- | --- | --- |
| 1 | `OBSERVED`, `observed_by = client`, registered source, `ap-…` shape | **accepted** | accepted |
| 2 | `OBSERVED` without a side / `null` side / unknown side | **rejected** | accepted (no side to compare) |
| 3 | `OBSERVED` with the **worker** side | **rejected** (the registered side of `app_id` is the client side) | accepted |
| 4 | legacy flat value (`"ap-…"`) | **rejected** (names no side) | accepted |
| 5 | the fact is missing | **rejected** (the run has to record its application id as a typed fact) | accepted |
| 6 | `NOT_AVAILABLE` with a verified evidence reference of the EVM sandbox stage | **accepted** (unchanged) | accepted |
| 7 | `NOT_AVAILABLE` without a verified evidence reference | **rejected** (unchanged) | rejected |
| 8 | unknown status | **rejected** | rejected |

Case 6 is deliberately **not** side-checked: a `NOT_AVAILABLE` fact is an **absence claim**, not an observation claim — it states that the value could not be observed, not that it was observed from a side. The artifacts of Iteration 21 carry exactly that shape, and they stay valid in the strict mode.

The billing cross-check is **not** touched: `cross_check_app_ids()` keeps the run-level scope `modal_app_id` and compares an observed run-level application id with the raw billing export; it is exercised by the validator of this closure.

### 4.3 What the fixes do **not** do

* they do **not** change the producer (`modal_app.py`) and do **not** change the registry;
* they do **not** change the metric computation: the confusion matrix still runs only over a fully `SUCCESS` baseline, and the fail-closed metrics stay `None` for a mixed run;
* they do **not** weaken the compatibility path: `strict_sources=False` reads the artifacts of Iterations 14–20 exactly as before, and no side is inferred or backfilled into any artifact;
* they do **not** accept a worker-side claim for a client field anywhere — the cross-side direction stays closed;
* they do **not** rewrite the historical 16-target run: it stays visibly **failed**.

---

## 5. The vertical chains that are affected

| requirement | producer → fact → validator → serializer → consumer | what changes |
| --- | --- | --- |
| a failed run is never a negative finding | adapter → `TargetExecutionArtifact` → `resolve_detection` → `details[]`, `target_artifacts[]` → the report | the status guard wins over the verdict branch; the report states `null` + `NOT_EVALUATED` |
| a completed run keeps its verdict semantics | adapter → `evaluate_baseline_run` → the confusion matrix | unchanged — `COMPILATION_ERROR` / `RUNTIME_REVERT` / `GENERATION_FORMAT_ERROR` / `SAFE_RUN` stay negative for a completed run |
| the run-level application id names its side | the EVM sandbox stage fact → the run-level fact → `validate_provider_observation_source` → the strict consumer → the billing cross-check | the strict consumer side-checks the run-level fact |
| the stage facts keep their registered side | the worker envelope / the client block → the stage facts → the strict stage loop | unchanged (Iteration 23) |
| the artifacts of Iterations 14–23 stay readable | the artifacts on disk → the **non-strict** validators → the compatibility path | unchanged |

---

## 6. The evidence of this closure

1. the **consolidated validator** `benchmarks/validate_consolidated_closure_evidence.py`:
   * the **P0 probes** at the **consumer boundary** — the real `evaluate_baseline_run()` and the real report path of `benchmarks/benchmark_runner.py`, not a helper: every combination of a non-`SUCCESS` status with the four negative verdicts is rejected as a negative finding;
   * the **P1 probes** at the **consumer boundary** — the real `validate_modal_invocation_provenance(..., strict_sources=True)`: a client-observed run-level application id passes; a missing, `null`, unknown, worker-side and flat run-level application id fails; the compatibility path still accepts the flat shape;
   * the **digest probe** — the tampered artifact has its digests **recomputed** from the bytes on disk, so a rejection can only come from the side rule and not from a stale digest;
   * the **pre-fix reproduction** — the rule of the pre-fix consumer is reproduced inside the validator and still accepts the defect: the checks are not vacuous;
   * the **vertical chains** — one complete **successful** chain (producer → capture → artifact → validator → billing join → manifests → evaluator → report) and one complete **failure** chain, each asserted end to end;
   * the **historical evidence** — the evidence validator of **every** iteration from 14 to 23 is executed: the validators of Iterations 19–23 still satisfy their own validator, and the validators of Iterations 14–18 still **fail** visibly — the 16-target run on disk predates the fixes of Iterations 14–18, and this closure does not change that;
   * the **report semantics** — the reconciliation table of §8 is asserted against the real report;
2. the **focused test suite** `tests/test_consolidated_closure_evidence_integrity.py`;
3. the **validation evidence** `benchmarks/evidence/consolidated_closure_validation_evidence.json`, bound to the exact code SHA of this closure; `--check` refuses a foreign SHA.

**No live Modal invocation is made, the provider is never queried, no worker is deployed and no GPU is used.** The `OBSERVED` branch of the producer is exercised in a **simulated** container context (a patched `modal.current_function_call_id`) and is called a simulation wherever it is mentioned.

---

## 7. The tests that must exist

`tests/test_consolidated_closure_evidence_integrity.py`:

| # | test | what it proves |
| --- | --- | --- |
| 1 | every combination of a non-`SUCCESS` status with the four negative verdicts | the report states `detected: null` and `detection_state: NOT_EVALUATED` — never a negative finding |
| 2 | a mixed baseline | the metrics stay `None` and the failed target stays `NOT_EVALUATED` |
| 3 | a completed run with a negative verdict | it stays a **negative** finding — the fix does not hollow out the verdict semantics |
| 4 | the report written by the real runner | the per-target record of a failed run carries `detected: null` |
| 5 | the strict consumer with a client-observed run-level application id | **accepted** |
| 6 | the same with a missing / `null` / unknown / worker side, a flat value and a missing fact | **rejected** |
| 7 | the same artifact with the digests **recomputed** | the rejection comes from the side rule, not from a stale digest |
| 8 | the compatibility path | the side-less artifacts of Iterations 14–20 stay valid |
| 9 | the successful vertical chain | producer → capture → artifact → validator → billing join → manifests → evaluator → report holds end to end |
| 10 | the failure vertical chain | a failed run is reported as failed everywhere, and never as a negative finding |
| 11 | the artifacts of Iterations 14–23 | the validators of Iterations 19–23 still pass, and the validators of Iterations 14–18 still fail visibly — the historical 16-target evidence stays failed |

The existing test that encodes the P0 defect is **corrected** (the assertion changes from `detected is False` to `detected is None`); its intent — a compilation failure is never a positive finding and never a verified breach — is preserved and strengthened.

---

## 8. The reconciliation of the report semantics

The report has to keep these apart, in **every** output:

| layer | meaning | field |
| --- | --- | --- |
| planned | the target was in the dataset and the adapter was asked to run it | `total_targets`, `target_count`, `planned_command`, `planned_argv` |
| attempted | the tool was actually invoked | `orchestration_status`, `argv`, `provider`, `timeout_sec` |
| executed | the execution completed | `status` / `execution_status` (`SUCCESS` / `FAILED` / `UNAVAILABLE`) |
| observed | a finding of that execution | `detected`, `detection_state`, `security_verdict`, `verified_breaches`, `replayed_breaches` |
| reported | the interpretation of the baseline | the metrics, `status_reason`, `completed_targets` |

| state | stays distinct as |
| --- | --- |
| unavailable | `status: UNAVAILABLE` + `unavailable_reason` + `detection_state: NOT_EVALUATED` |
| failed | `status: FAILED` + `security_verdict: EXECUTION_FAILURE` (or the adapter's own verdict) + `detection_state: NOT_EVALUATED` |
| unknown | no status claim is invented: a missing artifact is an absence, not a `false` |
| not run | `generation_outcome: NOT_RUN` / `evm_outcome: NOT_RUN` / `replay_status: NOT_ELIGIBLE` |
| no valid evaluation | `detection_state: NOT_EVALUATED` — a completed run whose verdict is `INFRA_ERROR`, and a baseline that carries it is `INCOMPLETE` with every metric `None` |

### 8.1 The two cases that stay **documented, not changed**

| case | why it is not changed by this closure |
| --- | --- |
| `INVARIANT_BREACH_UNREPLAYED` with `detected: false` | the oracle saw an invariant breach that the independent replay did not confirm. The wire value `false` means "not confirmed", not "no breach" — but the **verdict** next to it says exactly that, and changing the value would change the metric semantics of a completed run, which this closure does not touch |
| the target-side and the candidate-side compilation failure are one verdict | `benchmarks/adapters.py` cannot tell them apart: a target that does not compile was never audited, and a candidate that does not compile is a failed attempt. The distinction belongs to the producer, and the producer is not the defect of this closure |


---

## 9. What this closure does **not** claim

* It does not claim a live Modal validation: no invocation is made, the provider is never asked, no worker is deployed, no GPU is used and no paid compute is spent.
* It does not change the historical benchmark result: the 16-target run on disk still **fails** the Iteration 16–18 validators (0/16), and this closure does not change that and does not claim otherwise.
* It does not weaken the compatibility path, a validator or a test to make a report green.
* It does not merge PR #12 and does not touch `main`, PR #8 or the integration branch.
* It does not claim that the full chain is free of defects beyond the two that are confirmed here: the audit of §3 states what was checked and what was found.

---

## 10. The ancestry of the branch — measured at the current head of the PR branch

Measured in the worktree of the PR branch at the head that carries this matrix. Every number below is a measurement, not an estimate, and every one of them is reproducible with the command that is written next to it.

**Four refs have to be kept apart**, because they are three different things:

| ref | what it is | commit |
| --- | --- | --- |
| the **base of PR #12** | the branch the pull request is opened against — `integration/minimax-antigravity-reconciled` | `736f11d` |
| the **base of the iteration line** | the commit the PR branch was cut from — the tip of the upstream line that is already an ancestor of the PR head | `47e49b9` |
| the **tip of the upstream line** | the current head of `feat/empirical-benchmark-runner` — the line the PR branch has to be reconciled with | `7876f6e` |
| the **head of PR #12** | the head that carries this matrix — the branch under review | *this commit* |

The three upstream refs are **not** interchangeable: `736f11d` is the base of the pull request, `47e49b9` is the point where the iteration line was branched off, and `7876f6e` is where the upstream line stands **now**.

### 10.1 The two lines

| line | range | commits | in the PR branch? |
| --- | --- | --- | --- |
| the **upstream** line | `736f11d..7876f6e` (`feat/empirical-benchmark-runner`) | **34** | 32 of them (up to `47e49b9`) are already ancestors of the PR head; the last **2** (`9bc6ebf`, `7876f6e`) are not |
| the **iteration** line | `47e49b9..HEAD` (Iterations 14–23, this closure and its follow-up) | **62** | yes — it is the branch itself |
| the branch as a whole | `736f11d..HEAD` | **94** | 32 upstream + 62 iteration |

The history is **linear**: the merge base of `7876f6e` and the PR head is `47e49b9` — the PR branch is the upstream line up to `47e49b9` plus the iteration line on top of it. The upstream branch has since advanced by two commits.

### 10.2 The diffs

| comparison | command | result |
| --- | --- | --- |
| against the **base of the PR** | `git diff --shortstat 736f11d..HEAD` | **264 files changed, 92,002 insertions(+), 357 deletions(-)** |
| against the **current upstream tip** | `git diff --shortstat 7876f6e..HEAD` | **116 files changed, 46,840 insertions(+), 3,373 deletions(-)** |
| against the **base of the iteration line** | `git diff --shortstat 47e49b9..HEAD` | **93 files changed, 44,059 insertions(+), 1,277 deletions(-)** |

The 264 files of the first row are **251 added** and **13 modified**; nothing is deleted. The insertions of this matrix itself are counted in all three rows — it is one of the 264 files.

**These numbers already include the documentation commit that carries this matrix.** That commit adds exactly one commit to the iteration line and changes nothing but this file, so the diff stats above were measured with `git diff --cached --shortstat <ref>` **before** the commit was written: they are the numbers of the head that carries this matrix, not of its parent.

### 10.3 The files that both lines touch

The upstream line and the iteration line changed **11** files in common — this is the surface a squash or a rebase of the PR would have to reconcile:

```
.github/workflows/ci.yml
.gitignore
benchmarks/adapters.py
benchmarks/benchmark_runner.py
benchmarks/evaluator.py
benchmarks/evidence/modal_billing_join_table.json
benchmarks/protocol.py
core/schemas.py
modal_app.py
sandbox/runner.py
tests/test_real_benchmark_execution.py
```

The overlap grew from **10** to **11** because the closure itself changed `benchmarks/evaluator.py` (the P0 fix, commit `2909b47`): that file is now touched by both lines. It is **not** a conflict — the two upstream commits do not touch it (§10.4).

### 10.4 The merge test — what a merge of the upstream head would actually cost

The merge was **not** performed. It was recomputed with `git merge-tree --write-tree`, which touches neither the working tree nor any branch:

```
git merge-base 7876f6e HEAD
→ 47e49b9389753d6ce3a7075d0d1cef9cc2c5d5d7
git merge-tree --write-tree --name-only 7876f6e HEAD
→ CONFLICT (content): benchmarks/adapters.py
→ CONFLICT (content): benchmarks/benchmark_runner.py
→ CONFLICT (content): benchmarks/evidence/modal_billing_join_table.json
→ CONFLICT (content): benchmarks/protocol.py
→ CONFLICT (content): tests/test_real_benchmark_execution.py
```

**5 files conflict** — the same five as before, recomputed at the current head against the **actual current upstream tip** `7876f6e`. The two upstream commits touch **30** files; the other **25** (the artifacts of the run, `benchmarks/benchmark_results.json`, `benchmarks/evidence/modal_control_harness_validation.json`) are not touched by the iteration line and merge cleanly.

### 10.5 The safe minimal plan

| option | what it does | what it costs | verdict |
| --- | --- | --- | --- |
| **A — merge the upstream head into the PR branch** (`git merge 7876f6e` on the PR branch) | keeps both lines, adds one merge commit | 5 conflicts to resolve by hand; the resolutions belong to the maintainer of the two lines | **recommended** — it is the only option that preserves the published, SHA-bound evidence of Iterations 14–23 and of this closure, because every one of them names a commit of this branch |
| B — rebase the 62 iteration commits onto `7876f6e` | one linear history | rewrites 62 published commits; every SHA-bound evidence file of Iterations 14–23 and of this closure would have to be regenerated, and the published reports would no longer name an ancestor of the head | not recommended |
| C — squash the iteration line into the upstream line | one commit per logical change | the same as B, plus the loss of the per-iteration evidence chain | not recommended |
| D — leave the branch as it is | the PR stays 2 commits behind the upstream head | the 5 conflicting files stay unresolved until someone merges | acceptable as an interim state, but it should be stated, not hidden |

**This closure performs none of A, B or C.** No branch was merged, no branch was rebased, no shared branch was touched, and `main`, PR #8 and the base branch `integration/minimax-antigravity-reconciled` are untouched.

**The recommended order for the maintainer:**

1. resolve the 5 conflicts of option A — `benchmarks/protocol.py`, `benchmarks/benchmark_runner.py` and `benchmarks/adapters.py` are code, `benchmarks/evidence/modal_billing_join_table.json` is a regenerated table, `tests/test_real_benchmark_execution.py` is a test file;
2. re-run the evidence validator of this closure (`python -m benchmarks.validate_consolidated_closure_evidence --check`) — it executes the evidence validator of every iteration from 14 to 23, so a wrong resolution of the 5 files shows up there;
3. only then merge the PR into the integration branch.

---

## 11. The results of this closure

### 11.1 The commits

| # | commit | what it carries |
| --- | --- | --- |
| 1 | `8a1d754` | **this matrix**, written and committed **before** any code change |
| 2 | `2909b47` | the **P0** and **P1** fixes in the contract and the evaluator, the new focused suite, and the correction of the one test that encoded the defect |
| 3 | `0a17ac6` | the **consolidated validator** |
| 4 | `2129059` | the two CI steps: the focused suite and the validator |
| 5 | `c5a371b` | the smoke probe of the closure keeps the checkout clean |
| 6 | `029eb7f` | the git manifest of the smoke probe is resolved from the repository |
| 7 | `1c75495` | the first published evidence of the closure |
| 8 | `810e89c` | the **independent review** of the validator and the matrix, and the rework it forced: the historical contract is now **executed**, the vacuous checks are gone, and the probe directory is ignored by git |
| 9 | `b3fbda7` | the completed matrix and the re-published evidence (17 checks), bound to the code SHA `810e89c74b525d7c0c351b85a9998ee880f4544d` |
| 10 | *this commit* | the pointer of this matrix at the final CI run |

### 11.2 The validator

`benchmarks/validate_consolidated_closure_evidence.py` — **17 checks, 17 passed**, bound to the code SHA of the closure:

| check | what it proves |
| --- | --- |
| P6.1 | the strict consumer **accepts** a client-observed run-level application id |
| P6.2 | the strict consumer **rejects** the missing, the null, the unknown and the worker side, the legacy flat value, the unknown status and the missing fact |
| P6.3 | the rejection comes from the **side rule** and not from a stale digest — the digests are recomputed from the bytes on disk |
| P6.4 | the **compatibility path** still reads the side-less artifacts of Iterations 14–20 in every shape the pre-fix code accepted |
| P6.5 | **every** combination of a non-success status and the negative verdicts, and every verdict that declares the audit itself invalid, is reported as `null` / `NOT_EVALUATED` — in the detail row **and** in the report record, with no breach counter and with the raw claim of the producer preserved |
| P6.6 | the mixed baseline stays non-scorable and keeps the failed target out of the findings |
| P6.7 | a completed run keeps its negative verdict and its own detection, and the confusion matrix agrees with the report |
| P6.8 | the report of the **real runner** — with a **failing** execution in it — carries the detection state, keeps both views of a target in agreement and states the failed target as `NOT_EVALUATED` |
| P6.9 | the **successful** vertical chain holds end to end: the billing join is resolved against a **raw line item**, and the adapter and target manifests keep the failure visible and carry no detection value |
| P6.10 | the **failure** vertical chain keeps the failure visible |
| P6.11 | the **pre-fix** rule of the evaluator — the line quoted from the historical source — still turns a failed run into a negative finding: the defect was real |
| P6.12 | the **pre-fix consumer itself is executed**: the evidence contract of the commit before the closure is loaded from its historical source and **accepts** the side-less and the wrong-sided run-level application id — the defect was real |
| P6.13 | the evidence validator of **every** iteration from 14 to 23 is executed: 14–18 stay visibly **FAILED**, 19–23 stay **PASSED**; a stale report of an interrupted run can never be mistaken for a result |
| P6.14 | the producer source is byte-wise unchanged since the capture of Iteration 21 |
| P6.15 | the digest and the byte length of the stage evidence artifact are the ones of the bytes on disk |
| P6.16 | the closure runs in a **synthetic** context: the run of the real runner is a synthetic smoke test, and the `OBSERVED` branch of the producer was captured under the simulated container context |
| P6.17 | the report states **planned, attempted, executed, observed and reported** apart, and unavailable, failed and not-run stay distinct in every output |

**The follow-up of §12 added four checks (P6.18–P6.21) and re-bound the evidence to the code SHA of the follow-up — see §13.**


**The pre-fix reproduction is checked against the historical source, not against a strawman.** The line that P6.11 reproduces is the line of the repository before the fix:

```
git show 2909b47~1:benchmarks/evaluator.py
    det = False if (is_compile_err or a.security_verdict in ("RUNTIME_REVERT", "GENERATION_FORMAT_ERROR", "SAFE_RUN")) else (a.detected if a.status == ExecutionStatus.SUCCESS else None)
```

Executed verbatim against the eight combinations of a non-success status and the negative verdicts, that expression yields `False` in every one of them — and the current resolver yields `None` in every one of them. The rule of P6.12 reproduces the consumer of the run-level application id before the fix, which looked at the run-level fact **only** in its `NOT_AVAILABLE` shape and accepted every other shape without a side check.


### 11.3 The local test runs — exact raw counts

These are the **local** numbers of this machine (Windows, Python 3.10, **no Foundry installed**). They are never mixed with the CI numbers of §11.4.

| run | result |
| --- | --- |
| the focused suite `tests/test_consolidated_closure_evidence_integrity.py` | **45 passed** |
| the complete local regression `python -m pytest -q` | **832 passed, 7 skipped** in 98.67 s (before the closure: 787 passed, 7 skipped — the difference of 45 is exactly the new suite) |
| the evidence validator of this closure | **17/17 checks passed** |
| the evidence validator of this closure in `--check` mode | `published PASSED, revalidated PASSED (17/17 checks), bound to 810e89c7…` |
| the evidence validators of Iterations 14–18 (re-run locally) | **FAILED, 16/16 targets failed** — the historical 16-target run stays visibly failed |
| the evidence validators of Iterations 19–23 (re-run locally, bound to their own code SHA) | **PASSED** — 12/12, 12/12, 13/13, 11/11, 12/12 |

### 11.4 The CI run — these are CI numbers, never mixed with the local ones

**Run [`42832300015`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42832300015)** on the head `b3fbda7` — both jobs **success**.

| job | step | raw result |
| --- | --- | --- |
| Reward v2 and trusted harness regression suite | the trusted evidence and reward contract tests | 58 passed; 25 passed; 23 passed, 4 skipped |
| | Iteration 14 | 73 passed, 3 skipped |
| | Iteration 15 | 33 passed |
| | Iteration 16 | 27 passed |
| | Iteration 17 | 65 passed |
| | Iteration 18 | 44 passed |
| | Iteration 19 | 24 passed |
| | Iteration 20 | 33 passed |
| | Iteration 21 | 41 passed |
| | Iteration 22 | 28 passed |
| | Iteration 23 | 34 passed |
| | **consolidated closure** | **45 passed** |
| | GRPO, GRPO integrity, trajectory integrity, round-5 regression | 6 passed; 5 passed; 5 passed; 6 passed |
| | **the complete test suite** | **828 passed, 11 skipped** |
| Real Foundry EVM integration probe | the live Foundry integration tests | **4 passed**, 65 deselected |
| | the live Foundry tests of Iteration 14 | **3 passed**, 73 deselected |
| | the billing join table | `join table validation: PASSED (no error)` |
| | the validator of Iteration 14 | `FAILED (0/16 targets), bound to 43436b02…` — **the historical evidence stays visibly failed** |
| | the validator of Iteration 15 | `FAILED (0/16 targets), bound to cf262236…` |
| | the validator of Iteration 16 | `FAILED (0/16 targets), bound to b1946536…` |
| | the validator of Iteration 17 | `FAILED (0/16 targets), bound to e9faff40…` |
| | the validator of Iteration 18 | `FAILED (0/16 targets), bound to 8813cebd…` |
| | the validator of Iteration 19 | `published PASSED, revalidated PASSED (12/12 checks), bound to 18ad9740…` |
| | the validator of Iteration 20 | `published PASSED, revalidated PASSED (12/12 checks), bound to 64392a7b…` |
| | the validator of Iteration 21 | `published PASSED, revalidated PASSED (13/13 checks), bound to 40c06309…` |
| | the validator of Iteration 22 | `published PASSED, revalidated PASSED (11/11 checks), bound to f0ce026d…` |
| | the validator of Iteration 23 | `published PASSED, revalidated PASSED (12/12 checks), bound to 749cba24…` |
| | **the validator of the consolidated closure** | **`published PASSED, revalidated PASSED (17/17 checks), bound to 810e89c7…`** |

The earlier run of the closure, [`42827984060`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42827984060) on the head `1c75495`, is green as well — it carries the first publication of the evidence (16 checks at that time).

The local suite and the CI suite run the **same 839 tests** on different platforms, and the two numbers are reported separately and are never added together:


| | passed | skipped | the skips |
| --- | --- | --- | --- |
| local (Windows, no Foundry, no Slither, a local `solc`) | **832** | **7** | 6 × "Real Foundry integration unavailable on system PATH", 1 × "Real Slither integration unavailable" |
| CI, the complete suite of the *tests* job (Linux, no Foundry, no Slither, no prebaked `solc` on the PATH) | **828** | **11** | the same 6 × Foundry + 1 × Slither, plus 4 × "real solc" of `tests/test_contract_normalization_v2.py` |

The six Foundry tests that the *tests* job skips are executed by the **foundry** job of the same run and **pass** there (4 passed, 65 deselected; and 3 passed, 73 deselected for the Iteration 14 subset).


### 11.5 The independent review

The validator and the matrix were reviewed **independently**, against the contract of this closure, and the review changed the deliverable. The findings and what happened to them:

| # | finding | severity | what was done |
| --- | --- | --- | --- |
| R1 | the pre-fix reproduction of the **P1** was a constant (`return True, None`): the historical half of the check could never fail, so the claim "the pre-fix rules are reproduced" was not proven | **critical** | the historical evidence contract is now **loaded from its historical source** (`git show 2909b47~1:benchmarks/evidence_integrity.py`) and **executed** — it accepts the side-less and the wrong-sided run-level application id, and the current contract refuses them (P6.12) |
| R2 | the boundary check compared a literal with itself — it could not fail | **critical** | the check now proves real facts: the run of the real runner is a `SYNTHETIC_SMOKE_TEST`, and the captured function-call id is the patched one, so the `OBSERVED` branch of the producer was exercised in the simulation. The declarative part (no deployment, no GPU) is published as `declared`, not as a comparison that pretends to be a proof (P6.16) |
| R3 | the check of the report of the real runner passed on an **empty** baseline and never exercised the failure path | major | a failing adapter is injected into the **real** runner, the report must contain a failed target, and both views of that target must state `NOT_EVALUATED` (P6.8) |
| R4 | the extended rule (`INFRA_ERROR`, `CHEATCODE_DETECTED`) was claimed to be closed but was not probed by the validator | major | both verdicts are now probed in P6.5 and P6.7; the historical reproduction (P6.11) probes exactly the verdicts of the pre-fix code |
| R5 | the check of the historical evidence could pass on the **stale report** of an interrupted run, and the exit code was not checked | major | the report of every iteration is deleted before the run, the exit code has to be `0`, and the output has to state the expected status (P6.13) |
| R6 | two links of the vertical chain were self-comparisons, and the manifests were missing | major | the billing join is resolved against a **raw line item** of the export, and the adapter and target manifests of the real runner are checked (P6.9) |
| R7 | the compatibility path was only checked for one shape | minor | every shape the pre-fix code accepted is checked: flat, side-less, missing and unknown status (P6.4) |
| R8 | the leak probes did not check the report record, the breach counters or the preserved raw claim, and the `leaked` flag was computed wrongly | minor | all of them are checked now (P6.5) |
| R9 | the `--check` mode did not compare the checkout with the bound SHA, and it refused a short SHA | minor | the files of the closure are compared between the bound commit and `HEAD`, and a short SHA is resolved (P6.14) |
| R10 | an unhandled exception would have produced **no report at all** instead of a failed one | minor | the validation is wrapped: an exception is reported as a failure, and the probe directory is always removed |
| R11 | the matrix contradicted itself about the expected state of the validators of Iterations 14–18 | minor | the wording is corrected in §7 and §9 of this matrix |

**The second, independent review of the P0 and the P1 fixes themselves** is the one of §11.5a below.


### 11.5a The focused review of the P0 and the P1 fixes themselves

A second review — **focused on the code** of the two fixes (`benchmarks/evaluator.py`, `benchmarks/evidence_integrity.py`), not on the validator and not on this matrix — returned **PASS** for both points of the contract and **10 findings**: 2 major and 8 minor. Every finding was checked against the code by hand before it was accepted or rejected; none of them was taken on trust.

| # | finding | severity | decision |
| --- | --- | --- | --- |
| R12 | the docstring of `validate_run_level_application_id()` promises that the consumer "may not let it contradict the stage copy of the same field", but **no value is ever compared**: the run-level fact and the stage copy are checked against the billing export **separately**, so one artifact may state **two different** application ids for one invocation — the run-level `ap-A…` next to the stage copy `ap-B…`, or next to a stage copy that says `NOT_AVAILABLE` | major | **fixed by this follow-up** — §12.1 |
| R13 | the resolver treats every verdict that is not `INFRA_ERROR` as a valid evaluation: a `SUCCESS` artifact **without** a verdict (`security_verdict = None`) counts as a negative finding | major | **not changed** — the semantics are the ones of §8.1 and the ones of the producer; §12.4 states why |
| R14 | a `NOT_AVAILABLE` run-level fact may carry a value; the client block refuses exactly that | minor | **fixed by this follow-up** — §12.2 |
| R15 | the two views of one target disagree about the breach counters: the report record zeroes them only for `NOT_EVALUATED`, the detail row also for a compilation error | minor | **fixed by this follow-up** — §12.3 |
| R16 | a run **without** a target is scored: `precision` / `recall` / `f1` are `0.0` and `candidates_per_verified_finding` is `inf`, and `json.dump` writes `Infinity` — an invalid JSON | minor | **fixed by this follow-up** — §12.3 |
| R17 | a negative verdict keeps the raw claim of the producer nowhere: a `CHEATCODE_DETECTED` run is presented as `detected: false` next to `verified_breaches: 1`, and the claim the producer made is lost | minor | **fixed by this follow-up** — §12.3 |
| R18 | the per-target artifact file on disk keeps the raw `"detected": false` of a failed target, without a `NOT_EVALUATED` marker | minor | **not changed** — the hashed artifact is evidence; only the presentation is normalized (§4.1) |
| R19 | `validate_run_level_application_id()` is public and defaults to `strict=False` | minor | **not changed** — the default **is** the compatibility path; the strict branch is the opt-in contract of Iterations 21–23 |
| R20 | the run-level error is raised before the errors of the stages, so a wrong source masks the diagnostics of the stage | minor | **not changed** — the side rule keeps its precedence, and the contradiction rule of §12.1 is evaluated **after** it |
| R21 | a target without a ground-truth entry is marked `is_vulnerable = false` in the detail row | minor | **not changed** — the metric path raises a `KeyError` for such a target, so no metric is ever computed from it |

Two of the findings deserve one more sentence each, because they are the ones that would have been easy to get wrong.

**R12 is a real gap of the closure, not a wording problem.** The intent of the closure is stated in §2.2 of this matrix: *"the strict mode accepts two contradictory statements about the same application id in one artifact"*. The rule of §4.2 closes the **side** dimension of that contradiction — a run-level fact that names the wrong side is refused — but the **value** dimension was never closed: the run-level fact and the stage copy of the same field are two statements about the same application id, and nothing compared them. The follow-up closes it.

**R13 is not a defect in the state of the producer.** A `SUCCESS` artifact means that the execution **completed**: the producer sets that status only after the audit ran, and the LLM auditor adapters never set a verdict at all (`benchmarks/adapters.py:805`). Treating a missing verdict as "not evaluated" would make every LLM-auditor baseline **unscoreable** — a fail-closed rule that refuses the legitimate negative finding of a baseline that ran and found nothing. The follow-up therefore states the rule exactly as it is implemented instead of changing it (§12.4).


### 11.6 The boundary of this closure

| claim | state |
| --- | --- |
| a live Modal invocation | **none** — the `OBSERVED` branch of the producer was exercised in a simulated container context (a patched `modal.current_function_call_id`) and is called a simulation |
| a provider query | **none** |
| a deployment, a redeployment, a worker restart | **none** |
| a GPU (H100 / T4), a paid compute | **none** |
| the producer `modal_app.py` | **unchanged** — P6.14 proves it byte-wise against the commit the capture of Iteration 21 was made from |
| the historical 16-target benchmark evidence | **still visibly failed** — the validators of Iterations 14–18 report `FAILED (0/16 targets)` in CI |
| the compatibility path | **unchanged** — the artifacts of Iterations 14–20 are read exactly as before, and no side is inferred or backfilled into any artifact |
| a merge, a rebase of a shared branch | **none** — the merge of the upstream head was only *computed* with `git merge-tree`, which touches neither the working tree nor any branch |

---

## 12. The follow-up — the contradiction rule and the presentation rules

The follow-up closes **R12**, **R14**, **R15**, **R16** and **R17**. It is written **before** the code, like the closure itself, and it is a part of the same closure — not a new iteration.

### 12.1 Rule F1 — the run-level application id may not contradict the stage copy

The run-level application id **is** the application id of the EVM sandbox stage of the same invocation: the producer writes the very same fact in both places (`benchmarks/adapters.py:2366`). The two are therefore **one fact in two places**, and the strict consumer may not let them contradict each other.

| the stage copy `stages.evm_sandbox.app_id` | the run-level fact | strict mode |
| --- | --- | --- |
| `OBSERVED` with the value `V` | `OBSERVED` with **the same** value `V` | **accepted** |
| `OBSERVED` with the value `V` | `OBSERVED` with another value | **rejected** — the two copies of one fact disagree |
| `NOT_AVAILABLE` | `OBSERVED` | **rejected** — the run claims an application id that the stage copy states it could not observe |
| `NOT_AVAILABLE` | `NOT_AVAILABLE` | **accepted** — two absence claims agree |
| `OBSERVED` with the value `V` | `NOT_AVAILABLE` | **accepted** — an absence claim is not an observation claim; the strict mode does not side-check an absence claim either, and the two statements are compatible: the stage copy may carry a **client-side** observation while the run-level copy states that the **worker** could not read it. This is the shape of the artifacts of Iteration 21 and of the probes of Iteration 23 |
| a legacy flat value | any | the strict loop over the stages refuses the flat value on its own; the contradiction rule adds no second reason to the same refusal |
| the stage `evm_sandbox` is absent | any | the rule does not fire — the stages are not mandatory (§3.1, F7), and this follow-up does not make them mandatory |

**The precedence is fixed.** The side, the source and the shape of the run-level fact are checked **first**, so a wrong-sided claim is still refused by the **side rule** (P6.3 stays true); only a claim that passed the side rule is compared with the stage copy.

**The rule is one-directional, and that is a decision.** An **absence claim** is not compared with the stage copy. The strict mode does not side-check an absence claim either — that is the contract of Iteration 21, and the artifacts of Iteration 21 and the probes of Iteration 23 have exactly that shape: the stage copy carries a client-side observation of the application id while the run-level copy states that the worker could not read it. Refusing that combination would have broken the published evidence of Iteration 23, and the two statements are in fact compatible: they are the observations of two **different** sides.

**The compatibility path is untouched.** The whole rule lives in the strict branch.

### 12.2 Rule F2 — an absence claim carries no value

A `NOT_AVAILABLE` run-level fact that holds a value is refused, exactly as the client block refuses it (`benchmarks/evidence_integrity.py`, the client-observed facts). `value: null` is **not** a value: the artifact of Iteration 21 carries exactly that and stays valid.

### 12.3 Rule F3 — one presentation rule for both views of a target

| what | the rule |
| --- | --- |
| the presented detection | the one of `resolve_detection()` — `true`, `false` or `null` |
| the presented breach counters | the raw counters **only** when the presented detection is a positive finding; otherwise `0` — a report never shows a breach count next to a target that found nothing |
| the raw claim of the producer | preserved under `producer_detected`, `producer_verified_breaches` and `producer_replayed_breaches` **whenever the presented value differs from the raw one** — the raw claim is never lost and never presented as a finding |
| the two views of a target | the detail row and the report record use **one** rule |
| the aggregate counters | the sum of the **presented** counters — the metric and the per-target rows cannot disagree |
| a run **without** a target | not scorable: `INCOMPLETE` with an explicit reason. A run with no target has no metric at all, and it adds no `Infinity` to the report |

### 12.4 What the follow-up does **not** change

* it does **not** change the producer `modal_app.py` and does **not** change the registry;
* it does **not** change the metric computation of a normal run: for a positive finding the counters are the raw ones, and the confusion matrix is untouched;
* it does **not** weaken the compatibility path: `strict_sources=False` reads the artifacts of Iterations 14–20 exactly as before, and no side is inferred and no value is backfilled into any artifact;
* it does **not** turn the stages into mandatory ones (F7 of §3.1 stays open);
* it does **not** change the meaning of a **missing verdict** (R13): a completed execution is a valid evaluation unless its verdict names an invalid category (`INFRA_ERROR`). The LLM auditor adapters never set a verdict (`benchmarks/adapters.py:805`), so a missing verdict is the normal shape of a completed audit of those baselines and not a reason to discard their finding. The rule is now stated exactly as it is implemented, instead of the "semantically valid" wording of §4.1;
* it does **not** change the treatment of `INVARIANT_BREACH_UNREPLAYED` and of the mix of a target-side and a candidate-side compilation error — both stay documented limitations of §8.1;
* it does **not** rewrite the per-target artifact file on disk: its hash is in the manifest, and the file is evidence;
* it does **not** change the meaning of the **pre-existing** metric `candidates_per_verified_finding`, which is `inf` when a **scored** baseline has no verified breach — `json.dump` writes `Infinity` for it, and the committed `benchmarks/benchmark_results.json` carries one such value. That is the pre-existing behaviour of a published metric and is out of the scope of this follow-up; the follow-up removes only the **new** source of it, the run without a target, which is not scored at all.

### 12.5 The checks that must exist

| check | what it proves |
| --- | --- |
| P6.18 | the strict consumer **refuses** a run-level application id that contradicts the stage copy — the three contradicting cases of §12.1 |
| P6.19 | the strict consumer **refuses** a `NOT_AVAILABLE` run-level fact that carries a value |
| P6.20 | the **pre-fix contract of the follow-up** — the evidence contract of the published closure (`810e89c`) — is loaded from its historical source and **executed**: it accepts the contradictory artifact, so the gap was real and the check is not vacuous |
| P6.21 | the two views of a target agree about the counters, the raw claim is preserved whenever it differs from the presented one, and a run without a target is not scorable |

P6.1 is reworded: the strict consumer accepts a client-observed run-level application id **that agrees with the stage copy**. The probe of the acceptance builds an artifact that is consistent in both places, because an artifact that contradicts itself is refused by design.

### 12.6 The boundary of the follow-up

| claim | state |
| --- | --- |
| a live Modal invocation | **none** — the `OBSERVED` branch of the producer is exercised in a simulated container context, exactly as in §11.6 |
| a provider query, a deployment, a GPU, a paid compute | **none** |
| the producer `modal_app.py` | **unchanged** |
| the published evidence of Iterations 14–23 | **untouched** — their validators keep their own state, and the historical 16-target benchmark stays visibly failed |
| the compatibility path | **untouched** |
| the evidence of this closure | **re-bound** to the code SHA of the follow-up and re-published with the new checks |
| a merge, a rebase of a shared branch | **none** |

---

## 13. The results of the follow-up

### 13.1 The commits

| # | commit | what it carries |
| --- | --- | --- |
| 1 | `218da73` | the design of the follow-up: the review of §11.5a and the rules of §12 — **written before the code** |
| 2 | `b4aa020` | the correction of the rule: it is **one-directional**, because the mirrored direction contradicts the published contract of Iteration 23 (§12.1) |
| 3 | `690f39a` | the code of the follow-up: F1, F2 and F3, the eight new tests and the four new checks of the validator |
| 4 | `a9bb2df` | the re-published evidence, bound to the code SHA `690f39a125ef091dee61ae9f18550ab068587c4e` |
| 5 | `037838f` | the results of the follow-up and the pointer at the CI run |
| 6 | `89b2f82` | the **refresh of the ancestry** of §10 — documentation only: no code, no validator, no test and no published evidence |
| 7 | *this commit* | the **revision of §13.6 into a change log** and the refresh of the numbers of §10 to this head — documentation only: no code, no validator, no test and no published evidence |

### 13.2 The validator — **21 checks, 21 passed**

`benchmarks/validate_consolidated_closure_evidence.py --code-sha 690f39a` → `wrote benchmarks/evidence/consolidated_closure_validation_evidence.json: PASSED, 21/21 checks passed`; `--check --code-sha 690f39a` → `published PASSED, revalidated PASSED (21/21 checks), bound to 690f39a125ef091dee61ae9f18550ab068587c4e`.

The four checks of the follow-up:

| check | what it proves |
| --- | --- |
| P6.18 | the strict consumer **refuses** a run-level application id that contradicts the copy of the EVM sandbox stage — an observed value next to a stage copy that observed another value, and an observed value next to a stage copy that could not observe one — while an **absence claim** stays an absence claim and is not compared |
| P6.19 | the strict consumer **refuses** a `NOT_AVAILABLE` run-level fact that carries a value |
| P6.20 | the **pre-fix contract of the follow-up** — the evidence contract of the published closure (`810e89c`) — is loaded from its historical source and **executed**: it accepts the contradicting artifact, so the gap was real and the check is not vacuous |
| P6.21 | the two views of a target agree about the breach counters, the raw claim of the producer is preserved whenever it differs, and a run without a target is not scorable |

**The published evidence of the other iterations is untouched.** P6.13 executes the validator of every iteration from 14 to 23 with the current code: 14–18 stay visibly **FAILED** (0/16 targets), 19–23 stay **PASSED** (12/12, 12/12, 13/13, 11/11, 12/12).

### 13.3 The local test runs — exact raw counts

These are the **local** numbers of this machine (Windows, Python 3.10, **no Foundry installed**). They are never mixed with the CI numbers of §13.4.

| run | result |
| --- | --- |
| the focused suite `tests/test_consolidated_closure_evidence_integrity.py` | **53 passed** (before the follow-up: 45 — the difference of 8 is exactly the new tests) |
| the complete local regression `python -m pytest -q` | **840 passed, 7 skipped** in 91.16 s (before the follow-up: 832 passed, 7 skipped — the difference of 8 is exactly the new tests) |
| the evidence validator of this closure | **21/21 checks passed** |
| the evidence validator of this closure in `--check` mode | `published PASSED, revalidated PASSED (21/21 checks), bound to 690f39a12…` |
| the evidence validators of Iterations 14–18 | **FAILED, 16/16 targets failed** — the historical 16-target run stays visibly failed |
| the evidence validators of Iterations 19–23 | **PASSED** — 12/12, 12/12, 13/13, 11/11, 12/12 |

### 13.4 The CI run of the follow-up — these are CI numbers

**Run [`42839711601`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42839711601)** on the head `a9bb2df` — both jobs **success**.

| job | step | raw result |
| --- | --- | --- |
| Reward v2 and trusted harness regression suite | the trusted evidence and reward contract tests | 58 passed; 25 passed; 23 passed, 4 skipped |
| | Iteration 14 | 73 passed, 3 skipped |
| | Iteration 15 | 33 passed |
| | Iteration 16 | 27 passed |
| | Iteration 17 | 65 passed |
| | Iteration 18 | 44 passed |
| | Iteration 19 | 24 passed |
| | Iteration 20 | 33 passed |
| | Iteration 21 | 41 passed |
| | Iteration 22 | 28 passed |
| | Iteration 23 | 34 passed |
| | **consolidated closure** | **53 passed** |
| | GRPO, GRPO integrity, trajectory integrity, round-5 regression | 6 passed; 5 passed; 5 passed; 6 passed |
| | **the complete test suite** | **836 passed, 11 skipped** |
| Real Foundry EVM integration probe | the live Foundry integration tests | **4 passed**, 65 deselected |
| | the live Foundry tests of Iteration 14 | **3 passed**, 73 deselected |
| | the billing join table | `join table validation: PASSED (no error)` |
| | the validator of Iteration 14 | `FAILED (0/16 targets), bound to 43436b02…` — **the historical evidence stays visibly failed** |
| | the validator of Iteration 15 | `FAILED (0/16 targets), bound to cf262236…` |
| | the validator of Iteration 16 | `FAILED (0/16 targets), bound to b1946536…` |
| | the validator of Iteration 17 | `FAILED (0/16 targets), bound to e9faff40…` |
| | the validator of Iteration 18 | `FAILED (0/16 targets), bound to 8813cebd…` |
| | the validator of Iteration 19 | `published PASSED, revalidated PASSED (12/12 checks), bound to 18ad9740…` |
| | the validator of Iteration 20 | `published PASSED, revalidated PASSED (12/12 checks), bound to 64392a7b…` |
| | the validator of Iteration 21 | `published PASSED, revalidated PASSED (13/13 checks), bound to 40c06309…` |
| | the validator of Iteration 22 | `published PASSED, revalidated PASSED (11/11 checks), bound to f0ce026d…` |
| | the validator of Iteration 23 | `published PASSED, revalidated PASSED (12/12 checks), bound to 749cba24…` |
| | **the validator of the consolidated closure** | **`published PASSED, revalidated PASSED (21/21 checks), bound to 690f39a12…`** |

The follow-up was validated by **three** CI runs: [`42839711601`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42839711601) on the head `a9bb2df` (the code and the evidence), [`42840686482`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42840686482) on the head `037838f` (the final head of the follow-up) and [`42860708229`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42860708229) on the head `89b2f82` (the head that carries the refreshed §10) — both jobs **success** in every run. The second and the third run repeat the same raw results: the complete suite **836 passed, 11 skipped**, the closure suite **53 passed**, the Foundry probe **4 passed** and the Iteration 14 subset **3 passed**, the billing join table `PASSED (no error)`, the validators of Iterations 14–18 `FAILED (0/16 targets)` and of Iterations 19–23 `published PASSED, revalidated PASSED`, and the validator of this closure **`published PASSED, revalidated PASSED (21/21 checks), bound to 690f39a12…`**.

The local suite and the CI suite run the **same 847 tests** on different platforms, and the two numbers are reported separately and are never added together:

| | passed | skipped | the skips |
| --- | --- | --- | --- |
| local (Windows, no Foundry, no Slither, a local `solc`) | **840** | **7** | 6 × "Real Foundry integration unavailable on system PATH", 1 × "Real Slither integration unavailable" |
| CI, the complete suite of the *tests* job (Linux, no Foundry, no Slither, no prebaked `solc` on the PATH) | **836** | **11** | the same 6 × Foundry + 1 × Slither, plus 4 × "real solc" of `tests/test_contract_normalization_v2.py` |

The six Foundry tests that the *tests* job skips are executed by the **foundry** job of the same run and **pass** there (4 passed, 65 deselected; and 3 passed, 73 deselected for the Iteration 14 subset).

### 13.5 The boundary of the follow-up

| claim | state |
| --- | --- |
| a live Modal invocation, a provider query, a deployment, a GPU, a paid compute | **none** |
| the producer `modal_app.py` | **unchanged** — P6.14 proves it byte-wise against the commit the capture of Iteration 21 was made from |
| the published evidence of Iterations 14–23 | **untouched** — 14–18 stay visibly FAILED, 19–23 stay PASSED (P6.13) |
| the compatibility path (`strict_sources=False`) | **untouched** — the artifacts of Iterations 14–20 are read exactly as before, and no side is inferred and no value is backfilled into any artifact |
| the registry of the observation sources | **untouched** |
| the stages | **not** made mandatory — F7 of §3.1 stays open |
| a merge, a rebase of a shared branch | **none** |

### 13.6 The refreshes of the ancestry — a change log, not a second current-state report

This subsection is a **change log**. It does not describe the current state of the branch: it records what each refresh of this matrix measured, **at the head it was measured at**. The current state of the branch is described **once**, in §10 — the numbers there belong to the head that carries this matrix; the numbers of every entry below belong to the head that the entry names.

The head that the last review of the closure inspected was `89b2f82`: **93** commits ahead of the base of the PR, **61** commits of the iteration line, **264 files, +91,931 / −357**, and **2 commits behind** the tip of the upstream line `7876f6e`. The head that carries this matrix today is exactly one documentation commit ahead of it — its numbers are the ones in §10, and the delta is entry 3.

#### Entry 1 — the ancestry report as it was published in the closure (measured at `b3fbda7`)

The review of the closure at the head `037838f` confirmed the **code** of the closure (PASS for both points of the contract), the validator (21/21) and the CI run of that head (both jobs green), and found exactly **one** blocker: the ancestry report of §10 was still measured at the earlier head `b3fbda7`, while the head of the pull request was `037838f`.

| what | measured at `b3fbda7` |
| --- | --- |
| the commits against the base of the PR `736f11d` | 84 |
| the commits of the iteration line `47e49b9..HEAD` | 52 |
| the diff against the base of the PR | 264 files, +89,679 / −357 |

These numbers are **historical**. They describe the branch as it stood at `b3fbda7` and are kept here only as the starting point of this change log.

#### Entry 2 — the refresh of the ancestry of §10 (measured at `89b2f82`)

The refresh that closed the blocker of entry 1 changed **only this matrix**: no code, no validator, no test and no published evidence file was touched — the review forbade a code change, and none was made. The published evidence of Iterations 14–23 and of this closure is byte-wise untouched.

**What was refreshed**, every value measured at the head `89b2f82`:

| what | at `b3fbda7` | at `89b2f82` |
| --- | --- | --- |
| the commits against the base of the PR | 84 | **93** |
| the commits of the iteration line `47e49b9..HEAD` | 52 | **61** |
| the diff against the base of the PR | 264 files, +89,679 / −357 | **264 files, +91,931 / −357** |
| the diff against the current upstream tip `7876f6e` | 116 files, +44,514 / −3,370 | **116 files, +46,769 / −3,373** |
| the diff against the base of the iteration line `47e49b9` | 93 files, +41,733 / −1,274 | **93 files, +43,988 / −1,277** |
| the files that both lines touch | 10 | **11** — `benchmarks/evaluator.py` was added by the closure itself (`2909b47`) |
| the merge test against the current upstream tip | 5 conflicts | **5 conflicts** — the same five, recomputed with `git merge-tree` at `89b2f82` |
| the distance to the tip of the upstream line `7876f6e` | — | **2 commits behind** |
| the merge plan | option A, B, C, D | option A, B, C, D — unchanged in substance, with the commit counts of B and D refreshed |

The three refs are named apart in §10: the **base of the PR** (`736f11d` = `integration/minimax-antigravity-reconciled`), the **base of the iteration line** (`47e49b9`) and the **current tip of the upstream line** (`7876f6e` = `feat/empirical-benchmark-runner`).

**The CI run of that head — [`42860708229`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42860708229) on `89b2f82`, both jobs success.** These are the raw results, read out of the log of the run:

| job | step | raw result |
| --- | --- | --- |
| Reward v2 and trusted harness regression suite | the trusted evidence and reward contract tests | 58 passed; 25 passed; 23 passed, 4 skipped |
| | Iteration 14 | 73 passed, 3 skipped |
| | Iteration 15 | 33 passed |
| | Iteration 16 | 27 passed |
| | Iteration 17 | 65 passed |
| | Iteration 18 | 44 passed |
| | Iteration 19 | 24 passed |
| | Iteration 20 | 33 passed |
| | Iteration 21 | 41 passed |
| | Iteration 22 | 28 passed |
| | Iteration 23 | 34 passed |
| | **consolidated closure** | **53 passed** |
| | GRPO, GRPO integrity, trajectory integrity, round-5 regression | 6 passed; 5 passed; 5 passed; 6 passed |
| | **the complete test suite** | **836 passed, 11 skipped** |
| Real Foundry EVM integration probe | the live Foundry integration tests | **4 passed**, 65 deselected |
| | the live Foundry tests of Iteration 14 | **3 passed**, 73 deselected |
| | the billing join table | `join table validation: PASSED (no error)` |
| | the validator of Iteration 14 | `FAILED (0/16 targets), bound to 43436b02…` — **the historical evidence stays visibly failed** |
| | the validator of Iteration 15 | `FAILED (0/16 targets), bound to cf262236…` |
| | the validator of Iteration 16 | `FAILED (0/16 targets), bound to b1946536…` |
| | the validator of Iteration 17 | `FAILED (0/16 targets), bound to e9faff40…` |
| | the validator of Iteration 18 | `FAILED (0/16 targets), bound to 8813cebd…` |
| | the validator of Iteration 19 | `published PASSED, revalidated PASSED (12/12 checks), bound to 18ad9740…` |
| | the validator of Iteration 20 | `published PASSED, revalidated PASSED (12/12 checks), bound to 64392a7b…` |
| | the validator of Iteration 21 | `published PASSED, revalidated PASSED (13/13 checks), bound to 40c06309…` |
| | the validator of Iteration 22 | `published PASSED, revalidated PASSED (11/11 checks), bound to f0ce026d…` |
| | the validator of Iteration 23 | `published PASSED, revalidated PASSED (12/12 checks), bound to 749cba24…` |
| | **the validator of the consolidated closure** | **`published PASSED, revalidated PASSED (21/21 checks), bound to 690f39a12…`** |

**The published evidence is deliberately not regenerated.** `benchmarks/evidence/consolidated_closure_validation_evidence.json` stays bound to the code SHA `690f39a125ef091dee61ae9f18550ab068587c4e`; re-running the validator would rebind it to the head of a documentation commit and would break the chain of the evidence of Iterations 14–23, each of which names a commit of its own. **The code of the closure did not change in this refresh** — the head `89b2f82` carries exactly the code that the evidence names, `690f39a12…`, and the CI run above validated that same code.

#### Entry 3 — the revision of §13.6 into a change log (measured at *this commit*)

This commit changes **only this matrix**: it rewrites §13.6 into the change log above and refreshes the numbers of §10 to the head that carries them. No code, no validator, no test and no published evidence file is touched — the evidence stays bound to the code SHA `690f39a125ef091dee61ae9f18550ab068587c4e`, and the code of the closure is byte-wise identical to the code that the CI run `42860708229` validated.

| what | at `89b2f82` | at *this commit* |
| --- | --- | --- |
| the commits against the base of the PR `736f11d` | 93 | **94** |
| the commits of the iteration line `47e49b9..HEAD` | 61 | **62** |
| the diff against the base of the PR | 264 files, +91,931 / −357 | **264 files, +92,002 / −357** |
| the diff against the current upstream tip `7876f6e` | 116 files, +46,769 / −3,373 | **116 files, +46,840 / −3,373** |
| the diff against the base of the iteration line `47e49b9` | 93 files, +43,988 / −1,277 | **93 files, +44,059 / −1,277** |
| the files that both lines touch | 11 | **11** — unchanged |
| the merge test against the current upstream tip | 5 conflicts | **5 conflicts** — unchanged, recomputed with `git merge-tree` |
| the distance to the tip of the upstream line `7876f6e` | 2 commits behind | **2 commits behind** — unchanged |
| the merge plan | option A, B, C, D | option A, B, C, D — unchanged in substance |

This commit adds **exactly one** commit to the iteration line and changes **only this matrix**; the numbers of the right-hand column already include it — they were measured with `git diff --cached --shortstat <ref>` against each ref before the commit was written. The code did not change, so the CI run of this head validates exactly the same artifacts as `42860708229`; its id is published in the comment on the pull request.

**The boundary of every refresh recorded in this change log:**

| claim | state |
| --- | --- |
| a code change | **none** — the review forbade it, and none was made |
| a published evidence file | **none** — the evidence stays bound to `690f39a12…` |
| a merge, a rebase, a push to a shared branch | **none** — the merge of the upstream head was only *computed* with `git merge-tree`, which touches neither the working tree nor any branch |
| a live Modal invocation, a provider query, a deployment, a GPU, a paid compute | **none** |
| the benchmark result of the 16-target run | **unchanged** — it stays FAILED (0/16 targets) |

