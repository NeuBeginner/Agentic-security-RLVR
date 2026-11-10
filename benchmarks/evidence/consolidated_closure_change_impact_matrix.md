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

---

## 4. Design

### 4.1 Rule P0 — the fail-closed detection

> A **negative detection** exists only for a **successfully completed, semantically valid** execution. A run that did not complete — `FAILED`, `UNAVAILABLE` — has **no** finding: its detection is `null`, never `false`.

Implementation in `benchmarks/evaluator.py`:

| # | place | change |
| --- | --- | --- |
| 1 | a new resolver `resolve_detection(artifact)` | returns `(detection, detection_state)`: `None` / `NOT_EVALUATED` for a non-`SUCCESS` execution; `False` / `NEGATIVE` for a `SUCCESS` execution with one of the four negative verdicts; `bool(artifact.detected)` / `POSITIVE` or `NEGATIVE` otherwise |
| 2 | the per-target `details[]` row | `detected` comes from the resolver; the new `detection_state` names the state explicitly; the breach counters of a non-`SUCCESS` run are `0` (a run that did not complete cannot have verified a breach) |
| 3 | the per-target `target_artifacts[]` record of the report | the same resolver is applied, so a failed/unavailable record carries `detected: null` and `detection_state: NOT_EVALUATED`; the producer's raw claim is preserved under `producer_detected` |

**The state vocabulary of the report** becomes explicit:

| `detection_state` | meaning | `detected` |
| --- | --- | --- |
| `POSITIVE` | the execution completed and found a vulnerability | `true` |
| `NEGATIVE` | the execution completed and found nothing | `false` |
| `NOT_EVALUATED` | the execution did **not** complete — there is no finding | `null` |

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
   * the **historical evidence** — the validators of Iterations 14–23 still satisfy their own validators;
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
| 11 | the artifacts of Iterations 14–23 | their own validators still pass |

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

---

## 9. What this closure does **not** claim

* It does not claim a live Modal validation: no invocation is made, the provider is never asked, no worker is deployed, no GPU is used and no paid compute is spent.
* It does not change the historical benchmark result: the 16-target run on disk still **fails** the Iteration 16–18 validators (0/16), and this closure does not change that and does not claim otherwise.
* It does not weaken the compatibility path, a validator or a test to make a report green.
* It does not merge PR #12 and does not touch `main`, PR #8 or the integration branch.
* It does not claim that the full chain is free of defects beyond the two that are confirmed here: the audit of §3 states what was checked and what was found.

---

## 10. The ancestry of the branch — measured at the head of this closure

Measured in the worktree of the PR branch against the base of PR #12 (`736f11d` = `integration/minimax-antigravity-reconciled`) and the current upstream head (`7876f6e` = `feat/empirical-benchmark-runner`).

<!--ANCESTRY-->

---

## 11. The results of this closure

<!--RESULTS-->
