# Iteration 21 — Change Impact Matrix

**Iteration:** 21 (PR #12 follow-up)
**Scope:** make the **container identity** of a Modal run *provider-backed* instead of inferred from the environment — in the production producer (`modal_app.py`), in the evidence contract (`benchmarks/evidence_integrity.py`), in the client-side capture (`benchmarks/adapters.py`, new `benchmarks/modal_provider.py`) and in the validators.
**Trigger:** independent review comment [`issuecomment-6763944275`](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/12#issuecomment-6763944275) (2026-11-10).
**Authorization:** **no live Modal call is required**. No deployment, no redeployment, no restart, no modification of any live worker, no GPU (H100/T4), no paid GPU work, no production change.

---

## 1. Why this iteration exists

The Iteration 20 review was **NOT ACCEPTED**: the fix of the unsupported `modal.running_app()` calls was accepted, but the **container-identity path** was kept open as a P0.

> 1. `modal_app.py::capture_modal_runtime_identity()` still treats `MODAL_WORKER_ID` or `HOSTNAME` as an observed Modal container ID.
> 2. The Iteration 20 matrix itself says the SDK's worker ID is a configuration value used for internal debugging and that the Modal gVisor container may have no `HOSTNAME`. A generic `HOSTNAME` is not, by itself, proof of a provider-issued Modal container ID.
> 3. The tests set `MODAL_WORKER_ID` / `HOSTNAME` with monkeypatch and then exercise the OBSERVED branch. This proves that the producer copies an environment string; it does not prove that the string is a provider-issued container ID.
> 4. The client-side block now handles `app_id` and app-page URL, but does not provide a corresponding, independently verified client-side container identity.

All four findings are addressed by this iteration. The short version:

* the worker has **no supported source** of a provider-issued container id → it reports `NOT_AVAILABLE` with a precise reason;
* the **client** has one: the provider's own call graph ties the exact function call to the container that ran it → the client-side container id is a **provider-observed, invocation-correlated** fact;
* the contract now validates the **allowed observation sources**, not only the shape of an id and a free-form source string.

---

## 2. The actual source of truth — the installed Modal SDK 1.5.5

Every statement below was verified against the **installed** SDK (`modal 1.5.5`, `C:\Python310\lib\site-packages\modal`), not against documentation, memory or the shape of a name.

### 2.1 What a function container can observe (worker side)

| candidate | what the installed SDK actually says | verdict |
| --- | --- | --- |
| `modal.current_function_call_id()` | a **public** function (`modal/_runtime/execution_context.py`), exported in `modal.__all__`; returns the provider-issued `fc-…` of the current call, or `None` outside a container | ✅ **the only** provider-issued identifier a worker may attest itself |
| `modal.current_input_id()` | a **public** function, same mechanism (`in-…`) | ✅ usable as a runtime fact, not an identity field |
| `modal.is_local()` | a **public** function; `False` inside a Modal container | ✅ proof that the process is not local |
| `MODAL_WORKER_ID` | `modal/config.py:332` — `"worker_id": _Setting(),  # For internal debugging use.`; `modal/config.py:390` resolves a setting from the environment variable of the same name | ❌ **rejected**: an internal-debugging *configuration value*, not a provider-issued container identifier |
| `HOSTNAME` | nothing in the SDK ties the container hostname to a Modal container id | ❌ **rejected**: a generic hostname |
| `MODAL_TASK_ID` | read by `modal/experimental/flash.py:51` (`self.task_id = os.environ["MODAL_TASK_ID"]`) — an **experimental, internal** module, not part of `modal.__all__`; the env var is not documented as a public contract and is not guaranteed to be present in a plain function container | ❌ **rejected**: not a *supported* worker API |
| `modal.running_app` | a **module**, not a callable | ❌ already rejected in Iteration 20 |

The public runtime surface of the SDK is exactly `modal.__all__` (`modal/__init__.py:60-107`): `current_function_call_id`, `current_input_id`, `interact`, `is_local`. **There is no public worker-side API for a container id.**

### 2.2 What the client can observe (client side)

| source | what the installed SDK actually says | verdict |
| --- | --- | --- |
| `FunctionCall.get_call_graph()` | **public** method (`modal/_functions.py:2239`), reached through the **public** factory `FunctionCall.from_id(function_call_id)` (`modal/_functions.py:2273`); it returns `list[modal.types.InputInfo]` (`modal/types.py:145`), and `InputInfo` carries **`function_call_id`**, **`task_id`**, `function_name`, `module_name` | ✅ **the** source of a provider-issued container id |
| the provider's container listing | `modal container list` (`modal/cli/container.py:40-76`) prints the column **"Container ID"** from `TaskStats.task_id` and the column **"App ID"** from `TaskStats.app_id`; `modal/cli/app.py:189` documents the container id as **`ta-*`** | ✅ the provider's own record of which container belongs to which app |
| the provider's task record | `TaskGetInfo(task_id)` → `TaskGetInfoResponse.app_id` | ✅ an independent app↔container cross-check |
| `App.app_id` | `self._app_id`; the provider-issued `ap-…` id of the app; the SDK keeps it after the app has finished | ✅ the app id of the run (client side) |
| `App.get_dashboard_url()` | a supported public method returning `https://modal.com/id/<app_id>` | ✅ the app page URL (client side) |

**The provider's task id *is* the container id.** This is not an inference from the shape of a name: `modal/runner.py:216-222` — the SDK's own function is literally called `get_old_container_ids()` and returns `container.task_id`, and `modal/cli/container.py:69` prints exactly that field under the column heading *"Container ID"*.

**The correlation is exact.** The call graph of a function call contains, for every input of that call, the provider's own record of *which container executed that input* (`InputCallGraphInfo.function_call_id` + `InputCallGraphInfo.task_id`, rebuilt into the public `InputInfo` by `modal/call_graph.py`). The worker observes the `fc-…` of its own invocation; the client resolves that exact `fc-…` to the `ta-…` that ran it. An unrelated container of the same app can therefore never be attached.

**The honest caveat** (the SDK's own words, `modal/_functions.py:2242`): *"the call graph data is not populated in real-time, and its capture is best-effort. We do not recommend relying on this method for critical use cases."* The client-side container id is therefore reported only when the provider's record actually contains the invocation — otherwise it is `NOT_AVAILABLE` with the exact reason. It is never guessed and never taken from "a container of the same app".

---

## 3. Scope and authorization boundaries

| allowed | forbidden |
| --- | --- |
| the source of the production producer `modal_app.py` | any `modal deploy`, redeploy, restart or modification of a live worker |
| the shared evidence contract in `benchmarks/evidence_integrity.py` | any GPU (H100 / T4 / any other), any model loading, any paid GPU work |
| the client-side provider access in `benchmarks/modal_provider.py` and `benchmarks/adapters.py` | any live Modal invocation (not required for this iteration) |
| a new validator, a new focused test suite, a local producer capture | merging PR #12, touching `main`, PR #8 or the integration branch |
| running the focused tests, the full regression suite, the Foundry integration and CI | claiming a live validation, a benchmark validation or a provider-issued identity that was not observed |

**Stop conditions.** If the fix would require a deployment, a live worker, a GPU or a paid resource, the iteration stops and reports the blocker instead of weakening a validator or a test.

---

## 4. Design

### 4.1 The producer: the worker attests only what the SDK gives it

`capture_modal_runtime_identity()` no longer reads **any** environment variable. The `MODAL_WORKER_ID` / `HOSTNAME` lookup is gone from the source, not merely ignored.

| fact | side | how it is obtained |
| --- | --- | --- |
| `function_call_id` | worker | `modal.current_function_call_id()` — `OBSERVED` with that exact source, or `NOT_AVAILABLE` with the exact reason |
| `app_id` | worker | **not observable** → `NOT_AVAILABLE` with the exact reason (unchanged from Iteration 20) |
| `container_id` | worker | **not observable** → `NOT_AVAILABLE` with the **new** reason of Iteration 21: the SDK exposes no supported worker-side API for a provider-issued container id; `MODAL_WORKER_ID` is the internal-debugging `worker_id` configuration setting, `HOSTNAME` is a generic hostname, `MODAL_TASK_ID` belongs to an internal experimental module |
| `app_page_url` | worker | **not observable** → `NOT_AVAILABLE` with the exact reason (unchanged from Iteration 20) |
| `container_id_value` | worker | always `None` — the worker holds no container id at all |

### 4.2 The contract: the allowed observation sources are a closed list

A new registry in `benchmarks/evidence_integrity.py` names every source the repository accepts as provider-issued, together with the side it may be observed from and the shape of the value it may carry:

| field | side | allowed source | value shape |
| --- | --- | --- | --- |
| `function_call_id` | worker | `modal.current_function_call_id()` | `fc-…` |
| `app_id` | client | `App.app_id` | `ap-…` |
| `app_page_url` | client | `App.get_dashboard_url()` | `https://modal.com/id/ap-…` |
| `container_id` | client | the provider's call graph + container listing | `ta-…` |

`validate_runtime_identity_envelope(..., strict_sources=True)` applies the registry: an `OBSERVED` fact whose source is **not** in the registry is rejected, even when the value has a perfect provider shape. The strict mode is **additive**: the default stays permissive, so every artifact of Iterations 14–20 remains valid and no existing assertion is weakened.

`validate_client_observed_facts` additionally requires of a client-side `container_id`:

* the client side, and the registered client-side container source;
* the provider's shape `ta-…`;
* a **correlation record** that names the function-call id the worker observed, the application id of the run, and the provider records the value was taken from.

### 4.3 The client: a provider-observed, invocation-correlated container id

A new module `benchmarks/modal_provider.py` is the single place where the provider is asked, on the client side:

| call | provider record | used for |
| --- | --- | --- |
| `FunctionCall.from_id(fc).get_call_graph()` | `InputInfo.function_call_id` + `InputInfo.task_id` | the container that executed **this** invocation |
| `TaskList(app_id=…)` | `TaskStats.task_id` + `TaskStats.app_id` | the independent proof that the container belongs to **this** app |
| `TaskGetInfo(task_id)` | `TaskGetInfoResponse.app_id` | the second, independent app↔container cross-check |

The client-side container id is `OBSERVED` only when **all** of it holds: the call graph contains an input of exactly this function call; the container is listed for exactly this app; the provider's own task record names exactly this app. Otherwise it is `NOT_AVAILABLE` with the exact reason — an unrelated container of the same app is never attached.

### 4.4 The capture: the real producer, run locally, against a **hostile** environment

`benchmarks/run_iteration21_producer_capture.py` executes the **real** production producer against the installed SDK 1.5.5 with

* a **hostile environment**: `MODAL_WORKER_ID`, `HOSTNAME` and `MODAL_TASK_ID` are set to arbitrary, well-formed but **fake** values (`ta-spoofed-…`) — the capture proves that the producer ignores them instead of copying them;
* a **sentinel** on `modal.running_app` (as in Iteration 20): any access is recorded and the capture fails;
* the repository's own producer for the stage evidence artifact (`write_stage_evidence_artifact`);
* the **provenance consumer** on top of it: the `modal_invocation_provenance` block is built and validated with `validate_modal_invocation_provenance`.

**This is a local capture, not a live Modal invocation.** It holds **no** provider-issued identifier: outside a Modal container the function-call id is `NOT_AVAILABLE`, and no provider answered the client's questions, so the client-side container id is `NOT_AVAILABLE` too — exactly what the truth is at that moment.

### 4.5 The validator: the repository is validated, not a rehearsal of it

`benchmarks/validate_iteration21_evidence.py` re-reads the capture from disk, recomputes the digest of the stored bytes and runs the repository validators over them. It also checks the **source** of the producer, because the defect of Iteration 20 was a defect of the source:

* the producer source reads **no** environment variable for the container identity (checked on the parsed syntax tree);
* the envelope carries typed facts only, every fact names its side, and every `OBSERVED` fact of it names a **registered** source;
* the worker envelope holds **no** `OBSERVED` container id — ever;
* the client-side container id is a client-side fact with the provider's shape and a correlation record that matches the worker's function-call id and the app id of the run;
* the stage evidence artifact satisfies the unchanged Iteration 18 artifact contract, and its digest is the digest of the bytes on disk;
* the provenance block passes `validate_modal_invocation_provenance`;
* the report is bound to the code SHA it was produced from; `--check` refuses a foreign SHA.

---

## 5. Change Impact Matrix

| # | Requirement | Producer (evidence is created here) | Captured response | Runtime envelope | Validator / report | Accepted when | Positive test | Negative (adversarial) tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | The producer does not infer the container id from the environment | `modal_app.py::capture_modal_runtime_identity()` | the envelope the producer returns | the envelope itself | the validator parses the source of the producer and finds no environment lookup for the container id | the syntax tree of the producer reads no `MODAL_WORKER_ID`, no `HOSTNAME` and no `MODAL_TASK_ID` | `test_iteration21_the_producer_source_reads_no_environment_variable_for_the_container_id` | `test_iteration21_a_producer_that_reads_the_hostname_is_detected` |
| 2 | A spoofed environment cannot become an observed container id | the producer | — | `container_id` | the envelope schema | with `MODAL_WORKER_ID`, `HOSTNAME` and `MODAL_TASK_ID` set to fake values the container id stays `NOT_AVAILABLE` | `test_iteration21_a_spoofed_environment_does_not_become_an_observed_container_id` | — |
| 3 | The worker states exactly why it cannot attest its container id | the producer | — | `container_id` | the validator checks the exact reason | the fact is `NOT_AVAILABLE`, holds no value, and its reason is the producer's own | `test_iteration21_the_container_id_is_an_explicit_absence_with_the_precise_reason` | `test_iteration21_a_guessed_container_id_is_rejected` |
| 4 | The function-call id stays the worker's provider-issued anchor | the producer | — | `function_call_id` | the envelope schema + the source registry | an observed function-call id names `modal.current_function_call_id()` and has the `fc-…` shape | `test_iteration21_the_function_call_id_keeps_its_exact_source` | `test_iteration21_a_malformed_function_call_id_is_rejected` |
| 5 | Only registered sources may back an observed value | the producer (worker) and the client (client) | — | every fact of the envelope | `validate_runtime_identity_envelope(..., strict_sources=True)` | an observed fact names a registered source of the registry | `test_iteration21_the_registered_sources_are_accepted` | `test_iteration21_an_unregistered_source_is_rejected` |
| 6 | A worker-side observed container id is impossible | the producer | — | `container_id` | the envelope schema + the source registry | a worker-side `OBSERVED` container id is rejected | `test_iteration21_the_worker_envelope_holds_no_observed_container_id` | `test_iteration21_a_worker_side_observed_container_id_is_rejected` |
| 7 | The client-side container id is provider-observed | the client (`benchmarks/adapters.py`) | the client-observed block | — | the source registry + `validate_client_observed_facts` | the fact is client-side, names the registered container source and has the `ta-…` shape | `test_iteration21_the_client_side_container_id_is_provider_observed` | `test_iteration21_a_client_side_container_id_without_the_provider_source_is_rejected` |
| 8 | The client-side container id is correlated to **this** invocation | the client | the correlation record | the worker's `function_call_id` | the correlation check of `validate_client_observed_facts` | the correlation names the function-call id the worker observed and the app id of the run | `test_iteration21_the_client_side_container_id_is_correlated_to_the_invocation` | `test_iteration21_a_client_side_container_id_of_another_invocation_is_rejected` |
| 9 | An uncorrelated container of the same app is never attached | the client | — | — | the container-listing cross-check | a container that the provider does not list for the app yields `NOT_AVAILABLE` | `test_iteration21_a_container_listed_for_the_app_is_accepted` | `test_iteration21_an_uncorrelated_container_of_the_same_app_is_rejected` |
| 10 | A missing provider field is an explicit absence | the client | — | — | the absence reason | the client-side container id is `NOT_AVAILABLE` with the exact reason when the provider answered nothing | `test_iteration21_a_missing_provider_response_is_an_explicit_absence` | — |
| 11 | The producer → serialized response → stage evidence → provenance → report path holds | the **real** producer + `write_stage_evidence_artifact` + the provenance builder | the serialized response | the envelope of that response | `validate_stage_evidence_artifact` + `validate_runtime_identity_envelope` + `validate_modal_invocation_provenance` | the artifact satisfies the Iteration 18 contract, the envelope is the one the response carries, and the provenance block validates | `test_iteration21_the_producer_response_satisfies_the_evidence_contract` | `test_iteration21_a_detached_envelope_is_rejected` |
| 12 | The digest of the artifact is the digest of the bytes on disk | the capture stores the path and the SHA-256 of the written artifact | — | — | the validator recomputes the digest of the bytes | the recomputed digest equals the recorded digest | `test_iteration21_the_artifact_digest_matches_the_bytes_on_disk` | `test_iteration21_a_tampered_artifact_is_rejected` |
| 13 | The side of a fact survives the whole path | `build_stage_identity_facts` | — | — | the provenance block of the target artifact | the stage facts keep the side of the envelope they came from | `test_iteration21_the_stage_facts_keep_the_side_of_the_envelope` | `test_iteration21_a_client_observation_inside_the_worker_envelope_is_rejected` |
| 14 | The historical evidence stays valid | the shared contract | — | — | the validators of Iterations 14–20 | every artifact of Iterations 14–20 still validates | `test_iteration21_the_historical_evidence_stays_valid` | — |
| 15 | The evidence is bound to the code that produced it | the capture records the source commit SHA | — | — | the report is bound to that SHA; `--check` refuses a foreign SHA | the bound SHA is an ancestor of `HEAD` | `test_iteration21_the_validation_evidence_is_bound_to_the_code_sha` | `test_iteration21_the_check_mode_detects_a_foreign_code_sha` |
| 16 | No deployment, no live worker, no GPU | the capture declares the deployment state | — | — | the validator checks the declaration of the capture | the capture declares `"live_modal_invocation": false` and `"deployment": "none"` | `test_iteration21_the_capture_declares_no_live_invocation_and_no_deployment` | — |
| 17 | The new suite and the new validator run in CI | `.github/workflows/ci.yml` | — | — | the workflow references both | the workflow runs both | `test_iteration21_the_ci_workflow_runs_the_new_suite_and_the_new_validator` | — |
| 18 | The iteration is documented before it is coded | `benchmarks/evidence/iteration21_change_impact_matrix.md` | — | — | the matrix is committed before the code change | this file exists and states the boundary | `test_iteration21_the_change_impact_matrix_documents_the_iteration` | — |

---

## 6. The exact API of this iteration

| symbol | module | role |
| --- | --- | --- |
| `capture_modal_runtime_identity` | `modal_app.py` | the **fixed** production producer of the runtime-identity envelope |
| `MODAL_CONTAINER_ID_NOT_ATTESTABLE_REASON` | `modal_app.py` | the exact reason of the fact a worker cannot observe (Iteration 21) |
| `MODAL_CONTAINER_ID_UNAVAILABLE_REASON` | `modal_app.py` | the **Iteration 20** wording — kept unchanged, because the committed Iteration 20 capture and its validator refer to it |
| `PROVIDER_OBSERVATION_SOURCES` | `benchmarks/evidence_integrity.py` | the closed list of the sources that may back an observed value |
| `validate_provider_observation_source` | `benchmarks/evidence_integrity.py` | the rule that an observed value names a registered source of the registry |
| `validate_runtime_identity_envelope` | `benchmarks/evidence_integrity.py` | the envelope schema, extended by the optional strict source mode (additive) |
| `validate_client_observed_facts` | `benchmarks/evidence_integrity.py` | the client block, extended by the correlation rule of the container id |
| `MODAL_CONTAINER_ID_RE` | `benchmarks/evidence_integrity.py` | the provider's shape of a container id (`ta-…`) |
| `ModalProvider` | `benchmarks/modal_provider.py` | the client's access to the provider: call graph, container listing, task record |
| `_client_observed_container_id` | `benchmarks/adapters.py` | the client-side container id with its correlation record |
| `run_iteration21_producer_capture` | `benchmarks/run_iteration21_producer_capture.py` | the local capture of the real producer against a hostile environment |
| `validate_iteration21_evidence` | `benchmarks/validate_iteration21_evidence.py` | the validator of the capture, of the producer source and of the correlation |

---

## 7. Honest boundaries of this iteration

* **No live Modal call.** This iteration makes no Modal invocation at all: the capture runs the producer locally against the installed SDK. The report says so in its scope; it never claims a live validation.
* **No provider-issued identifier is produced.** Outside a Modal container the producer reports the function-call id and the container id as `NOT_AVAILABLE`, and no provider answered the client, so the client-side container id is `NOT_AVAILABLE` too — that is the truth of a local run, and the capture contains no invented id.
* **The `OBSERVED` branches are proven by tests, not by the capture.** The tests run the real producer in a simulated container context and the client against a **fake provider**; a simulation is called a simulation, and a mock is never presented as proof of a live Modal identity.
* **The deployed workers are not changed.** The source is fixed; nothing is deployed, redeployed or restarted. A new deployment is needed for the fix to reach a live worker — that is outside this iteration.
* **The call graph is best-effort.** The SDK itself documents it as such (`modal/_functions.py:2242`). The client-side container id is therefore reported only when the provider's record holds the invocation; it is never taken from "a container of the same app".
* **This is not a benchmark validation.** The 16-target run on disk still fails the Iteration 16–18 validators; this iteration does not change that and does not claim otherwise.
* **The CI counts and the local counts are reported separately** and are never mixed into one number.
* **No merge.** PR #12 stays open; the merge blocker of the reviewer (the commit-by-commit ancestry explanation and the minimal/reconciled diff plan) is not part of this iteration.

---

## 8. Files touched

| file | change |
| --- | --- |
| `modal_app.py` | the fixed production producer: no environment variable for the container identity, `NOT_AVAILABLE` with the new precise reason, no `container_id_value` |
| `benchmarks/evidence_integrity.py` | the registry of the allowed observation sources, the strict source mode of the envelope schema, the provider's container-id shape, the correlation rule of the client block |
| `benchmarks/modal_provider.py` | the client's access to the provider: call graph, container listing, task record |
| `benchmarks/adapters.py` | the client-side container id with its correlation record, added to the client-observed block |
| `benchmarks/run_iteration21_producer_capture.py` | the local capture of the real producer against a hostile environment |
| `benchmarks/validate_iteration21_evidence.py` | the validator: the producer source, the capture from disk, the repository validators, the correlation, the code-SHA binding |
| `benchmarks/evidence/iteration21_producer_capture/` | the artifacts of the capture (the stage evidence artifact and the capture record) |
| `benchmarks/evidence/iteration21_validation_evidence.json` | the published validation artifact, bound to the code SHA |
| `benchmarks/evidence/iteration21_change_impact_matrix.md` | this matrix |
| `tests/test_iteration21_evidence_integrity.py` | the focused test suite |
| `tests/test_iteration20_evidence_integrity.py` | the one test of Iteration 20 that asserted the defective behaviour (see §9) |
| `.github/workflows/ci.yml` | run the Iteration 21 suite and the Iteration 21 validator |

---

## 9. The one change to an earlier iteration, and why

`tests/test_iteration20_evidence_integrity.py::test_iteration20_the_observed_values_keep_their_exact_source` asserted that a value set in `MODAL_WORKER_ID` becomes an `OBSERVED` container id with the source *"MODAL_WORKER_ID/HOSTNAME of the running container"*. **That assertion is the defect the review names** — it proved that the producer copies an environment string, not that the string is a provider-issued container id.

The test is therefore changed: the function-call id keeps its exact source (that part was and stays correct), and the container id is now expected to stay `NOT_AVAILABLE` even when `MODAL_WORKER_ID` and `HOSTNAME` are set. The change **strengthens** the suite — a spoofed value can no longer pass as an observed provider identity — and it is stated here and in the PR comment, so it cannot be mistaken for a weakened test.

No other assertion of Iteration 14–20 is changed, and no validator is relaxed.

---

## 10. Results of this iteration

The local counts and the CI counts are reported **separately** and are never mixed into one number. They are filled in after the run — the numbers below are the ones of the actual run, not a plan.

<!-- RESULTS -->
