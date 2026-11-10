# Iteration 20 — Change Impact Matrix

**Iteration:** 20 (PR #12 follow-up)
**Scope:** fix the **production** runtime-identity capture of the deployed Modal workers — `modal_app.py::capture_modal_runtime_identity()` — and make the side of every observation (worker vs. client) explicit in the evidence contract.
**Trigger:** independent review comment [`issuecomment-6763225184`](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/12#issuecomment-6763225184) (2026-11-10).
**Authorization:** the reviewer requires **no live Modal call** for this iteration: no deployment, no redeployment, no restart, no change to any live worker, no GPU (H100/T4), no paid GPU work.

---

## 1. Why this iteration exists

The Iteration 19 review was **PARTIALLY ACCEPTED**: the live CPU-only smoke test was accepted as a bounded live test, but one **P0 defect of the production provenance path** remained open:

> `modal_app.py::capture_modal_runtime_identity()` still calls `modal.running_app()` twice (for the app id and for the app page URL). With Modal SDK 1.5.5 `modal.running_app` is a **module**, not a callable. Both calls raise and are swallowed, so deployed workers silently emit `NOT_AVAILABLE` for the app identity and the app URL. The smoke test uses a separate app and does not fix or validate the production workers.

The smoke app of Iteration 19 (`benchmarks/modal_cpu_smoke_app.py`) already contains the *correct* pattern; the **production** app still carries the broken one. This iteration therefore fixes the production producer and proves the fix — without touching any deployed worker.

### 1.1 The exact API of Modal SDK 1.5.5 (verified, not assumed)

Every statement below was verified against the **installed** SDK (`modal 1.5.5`, `C:\Python310\lib\site-packages\modal`), not against documentation or memory:

| symbol | what the installed SDK actually offers | consequence for the worker |
| --- | --- | --- |
| `modal.running_app` | a **module** (`modal/running_app.py`) that holds the `RunningApp` **dataclass** and the client-side helper `running_app_from_layout(app_id, app_layout, app_page_url)`; it is **not callable** | there is **no** running-app accessor a function container could call — a call would raise `TypeError: 'module' object is not callable` |
| `modal.current_function_call_id()` | a real function (`modal/_runtime/execution_context.py`) that returns the `ContextVar` value or `None` outside a container | the **only** provider-issued identifier a worker can attest itself |
| `modal.current_input_id()` | a real function, same mechanism | usable as a runtime fact, not an identity field |
| `modal.is_local()` | a real function; `False` inside a Modal container | proof that the process is not local |
| `MODAL_WORKER_ID` / `HOSTNAME` | the SDK reads the worker id from the `worker_id` **configuration setting**, which the runtime sets only for internal debugging; the gVisor container of Iteration 19 set **no** hostname | a worker cannot attest its own container identity |
| `MODAL_IMAGE_ID` | the image of the running container (immutable `im-…` id) | usable as a runtime fact |
| `App.app_id` (client side) | `self._app_id`; the provider-issued `ap-…` id of the app; the SDK comments say "**Kept after app finishes**" | the **client** can attest the application id of the run |
| `App.get_dashboard_url()` (client side) | a supported public method returning `https://modal.com/id/<app_id>`; raises `InvalidError` when the app was never run | the **client** can attest the app page URL |

The asymmetry is the point: **the worker can attest the function-call id only; the app id and the app page URL are client-side facts.**

---

## 2. Scope and authorization boundaries

| allowed | forbidden |
| --- | --- |
| the source of the production producer `modal_app.py` | any `modal deploy`, redeploy, restart or modification of a live worker |
| the shared evidence contract in `benchmarks/evidence_integrity.py` | any GPU (H100 / T4 / any other), any model loading, any paid GPU work |
| the client-side observation in `benchmarks/adapters.py` | any live Modal invocation (not required for this iteration) |
| a new validator, a new focused test suite, a local producer capture | merging PR #12, touching `main`, PR #8 or the integration branch |
| running the focused tests, the full regression suite, the Foundry integration and CI | claiming a live validation, a benchmark validation or a provider-issued identity that was not observed |

**Stop conditions.** If the fix would require a deployment, a live worker, a GPU or a paid resource, the iteration stops and reports the blocker instead of weakening a validator or a test.

---

## 3. Design

### 3.1 The producer: no unsupported API, no swallowed exception

`capture_modal_runtime_identity()` is rewritten so that it uses **only** the runtime-context APIs the installed SDK really offers to a function container:

| fact | side | how it is obtained |
| --- | --- | --- |
| `function_call_id` | worker | `modal.current_function_call_id()` — `OBSERVED` with that exact source |
| `app_id` | worker | **not observable** → `NOT_AVAILABLE` with the exact reason (SDK 1.5.5 exposes no running-app accessor; `modal.running_app` is a module; the runtime-context API carries no application id; the app id of the run is taken from the provider-issued `App.app_id` on the client side) |
| `container_id` | worker | `MODAL_WORKER_ID` / `HOSTNAME` when present, otherwise `NOT_AVAILABLE` with the exact reason (the worker could not attest its own container identity; the provider-issued container id is a client-side fact of the provider's container list) |
| `app_page_url` | worker | **not observable** → `NOT_AVAILABLE` with the exact reason (the worker's only candidate was the unsupported `modal.running_app`; the supported `App.get_dashboard_url()` is a client-side API) |
| `container_id_value` | worker | the raw value the worker saw (or `None`) — the plain value the replay response reports |

The two `modal.running_app()` calls are **gone**; there is no `try/except` that hides a failed API call any more. Every value that cannot be observed is an explicit `NOT_AVAILABLE` **with a precise reason**, and every observed value keeps the **exact** source it was read from.

### 3.2 The contract: the side of every observation is explicit

A fact may now name the side that observed it (`observed_by`): `"worker"` for a fact read inside the container, `"client"` for a fact read by the client from the provider. The rules:

* a fact may declare only a known side;
* a fact inside the **worker** envelope may not declare the client side — the envelope of a worker response is worker-side by construction;
* an `OBSERVED` fact whose source names the client side may not be labelled `"worker"` (and vice versa) — a client observation can never be presented as a worker observation;
* `NOT_AVAILABLE` facts are **not** restricted by their reason text: the reason of an absent worker fact is allowed to name the client side as the place where the value *is* available.

The rules are **additive**: a fact without `observed_by` stays valid, so every artifact of Iterations 14–19 remains valid and no existing assertion is weakened.

### 3.3 The client: the app id and the app page URL are attested on the client side

`benchmarks/adapters.py` records, next to the worker-side provenance, the facts the **client** observed from the provider:

| fact | side | source |
| --- | --- | --- |
| `app_id` | client | the provider-issued `App.app_id` of the running app (Modal SDK 1.5.5, client side) |
| `app_page_url` | client | the provider's own dashboard URL of the running app (`App.get_dashboard_url()`, Modal SDK 1.5.5, client side) |

They live in their own block (`client_observed`) and are **never** merged into the worker envelope. The provenance validator rejects a client-observed fact that is labelled as a worker observation, and rejects a client-observed application id that does not have the provider shape.

### 3.4 The capture: the real producer, run locally, labelled as a capture

`benchmarks/run_iteration20_producer_capture.py` executes the **real** production producer — `modal_app.capture_modal_runtime_identity()` — against the installed Modal SDK 1.5.5 in a controlled environment:

* a **sentinel** is installed on `modal.running_app`; if the producer touched it at all, the sentinel would record the access and the capture would fail;
* `MODAL_WORKER_ID` and `HOSTNAME` are removed, so the environment is the one of a gVisor function container;
* the returned envelope is serialized into a response of the shape a worker returns, and the **repository's own** producer writes the stage evidence artifact (`write_stage_evidence_artifact`).

**This is a local producer capture, not a live Modal invocation.** It contains **no** provider-issued identifier: the capture runs outside a Modal container, so the function-call id and the container id are `NOT_AVAILABLE` — exactly what the producer reports outside a container. The capture record states this in every field (`"kind": "local_producer_capture"`, `"live_modal_invocation": false`, `"deployment": "none"`).

The `OBSERVED` branches of the producer (function-call id, container id) are exercised by the **test suite** in a simulated container context — a simulation is called a simulation there.

### 3.5 The validator: the repository is validated, not a rehearsal of it

`benchmarks/validate_iteration20_evidence.py` re-reads the capture from disk, recomputes the digest of the stored bytes and runs the repository validators over them. It also checks the **source** of the producer, because the defect of Iteration 19 was a defect of the source:

* the producer source contains **no** call of `modal.running_app` (checked on the parsed syntax tree, not on a string);
* the envelope carries typed facts only and every fact names its side;
* the stage evidence artifact satisfies the Iteration 18 artifact contract;
* the envelope is the one the captured response carries;
* the flags describe exactly one state of the Iteration 17 state table;
* the client-observed facts are client-side, provider-shaped and never worker observations;
* the report is bound to the code SHA it was produced from; `--check` refuses a foreign SHA.

---

## 4. Change Impact Matrix

| # | Requirement | Producer (evidence is created here) | Captured response | Runtime envelope | Validator / report | Accepted when | Positive test | Negative (adversarial) tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | The producer no longer calls an API that does not exist | `modal_app.py::capture_modal_runtime_identity()` | the envelope the producer returns | the envelope itself | the validator parses the source of the producer and finds no call of `modal.running_app` | the syntax tree of the producer contains no `running_app` call | `test_iteration20_the_producer_source_contains_no_running_app_call` | `test_iteration20_a_producer_that_calls_running_app_is_detected` |
| 2 | The producer never even touches the unsupported module | the producer runs against a sentinel installed on `modal.running_app` | — | — | the capture record states that the sentinel was never touched | the sentinel recorded no access | `test_iteration20_the_producer_never_touches_the_running_app_module` | — |
| 3 | The application id is an explicit absence with a precise reason | the producer | — | `app_id` | the envelope schema + the validator check of the reason | `app_id` is `NOT_AVAILABLE` with the exact reason and holds no value | `test_iteration20_the_app_id_is_an_explicit_absence_with_the_precise_reason` | `test_iteration20_a_guessed_app_id_is_rejected` |
| 4 | The app page URL is an explicit absence with a precise reason | the producer | — | `app_page_url` | the envelope schema + the validator check of the reason | `app_page_url` is `NOT_AVAILABLE` with the exact reason and holds no value | `test_iteration20_the_app_page_url_is_an_explicit_absence_with_the_precise_reason` | `test_iteration20_a_fabricated_app_page_url_is_rejected` |
| 5 | An observed value keeps the exact source it was read from | the producer | — | `function_call_id`, `container_id` | the envelope schema | the source is the exact API or environment variable that produced the value | `test_iteration20_the_observed_values_keep_their_exact_source` | `test_iteration20_an_observed_fact_without_a_source_is_rejected` |
| 6 | Every fact names the side that observed it | the producer (worker) and the client (client) | — | every fact of the envelope | the envelope schema + the provenance validator | every fact declares `worker` resp. `client` | `test_iteration20_every_fact_of_the_envelope_names_its_side` | `test_iteration20_a_fact_with_an_unknown_side_is_rejected` |
| 7 | A client observation can never be presented as a worker observation | the client | — | — | the envelope schema + the provenance validator | a client-side fact inside the worker envelope is rejected | `test_iteration20_a_client_observation_inside_the_worker_envelope_is_rejected` | `test_iteration20_a_worker_observation_labelled_as_client_side_is_rejected` |
| 8 | The producer → serialized response → evidence validator path holds | the **real** producer + `write_stage_evidence_artifact` | the serialized response | the envelope of that response | `validate_stage_evidence_artifact` + `validate_runtime_identity_envelope` | the artifact satisfies the Iteration 18 contract and the envelope is the one the response carries | `test_iteration20_the_producer_response_satisfies_the_evidence_contract` | `test_iteration20_a_detached_envelope_is_rejected` |
| 9 | The digest of the artifact is the digest of the bytes on disk | the capture stores the path and the SHA-256 of the written artifact | — | — | the validator recomputes the digest of the bytes | the recomputed digest equals the recorded digest | `test_iteration20_the_artifact_digest_matches_the_bytes_on_disk` | `test_iteration20_a_tampered_artifact_is_rejected` |
| 10 | A malformed or synthetic identifier is rejected | the validators of the repository | — | — | `validate_modal_invocation_provenance` | a guessed app id, a synthetic container id and a malformed function-call id are rejected | `test_iteration20_the_provider_shapes_are_enforced` | `test_iteration20_a_synthetic_container_id_is_rejected` |
| 11 | The side of a fact survives the producer → provenance path | `build_stage_identity_facts` | — | — | the provenance block of the target artifact | the stage facts keep the side of the envelope they came from | `test_iteration20_the_stage_facts_keep_the_side_of_the_envelope` | — |
| 12 | The evidence is bound to the code that produced it | the capture records the source commit SHA | — | — | the report is bound to that SHA; `--check` refuses a foreign SHA | the bound SHA is an ancestor of `HEAD` | `test_iteration20_the_validation_evidence_is_bound_to_the_code_sha` | `test_iteration20_the_check_mode_detects_a_foreign_code_sha` |
| 13 | No deployment, no live worker, no GPU | the capture declares the deployment state | — | — | the validator checks the declaration of the capture | the capture declares `"live_modal_invocation": false` and `"deployment": "none"` | `test_iteration20_the_capture_declares_no_live_invocation_and_no_deployment` | — |
| 14 | The new suite and the new validator run in CI | `.github/workflows/ci.yml` | — | — | the workflow references both | the workflow runs both | `test_iteration20_the_ci_workflow_runs_the_new_suite_and_the_new_validator` | — |
| 15 | The iteration is documented before it is coded | `benchmarks/evidence/iteration20_change_impact_matrix.md` | — | — | the matrix is committed before the code change | this file exists and states the boundary | `test_iteration20_the_change_impact_matrix_documents_the_iteration` | — |

---

## 5. The exact API of this iteration

| symbol | module | role |
| --- | --- | --- |
| `capture_modal_runtime_identity` | `modal_app.py` | the **fixed** production producer of the runtime-identity envelope |
| `MODAL_APP_ID_UNAVAILABLE_REASON`, `MODAL_CONTAINER_ID_UNAVAILABLE_REASON`, `MODAL_APP_PAGE_URL_UNAVAILABLE_REASON` | `modal_app.py` | the exact reasons of the facts a worker cannot observe |
| `OBSERVATION_SIDE_WORKER`, `OBSERVATION_SIDE_CLIENT`, `OBSERVATION_SIDES` | `benchmarks/evidence_integrity.py` | the sides an observation may name |
| `observed`, `not_available` | `benchmarks/evidence_integrity.py` | the typed facts, extended by the optional side |
| `validate_observation_side` | `benchmarks/evidence_integrity.py` | the rule that a fact's side and source may not contradict each other |
| `validate_runtime_identity_envelope` | `benchmarks/evidence_integrity.py` | the envelope schema, extended by the side rule (additive) |
| `build_stage_identity_facts` | `benchmarks/evidence_integrity.py` | the producer of the per-stage facts, extended by the side |
| `_client_observed_app_id`, `_client_observed_app_page_url` | `benchmarks/adapters.py` | the client-side observation of the provider-issued app identity |
| `run_iteration20_producer_capture` | `benchmarks/run_iteration20_producer_capture.py` | the local capture of the real producer |
| `validate_iteration20_evidence` | `benchmarks/validate_iteration20_evidence.py` | the validator of the capture and of the producer source |

---

## 6. Honest boundaries of this iteration

* **No live Modal call.** This iteration makes no Modal invocation at all: the capture runs the producer locally against the installed SDK. The report says so in its scope; it never claims a live validation.
* **No provider-issued identifier is produced.** Outside a Modal container the producer reports the function-call id and the container id as `NOT_AVAILABLE` — that is the truth of a local run, and the capture contains no invented id.
* **The `OBSERVED` branches are proven by tests, not by the capture.** The tests run the real producer in a simulated container context; a simulation is called a simulation.
* **The deployed workers are not changed.** The source is fixed; nothing is deployed, redeployed or restarted. A new deployment is needed for the fix to reach a live worker — that is outside this iteration.
* **This is not a benchmark validation.** The 16-target run on disk still fails the Iteration 16–18 validators; this iteration does not change that and does not claim otherwise.
* **The CI counts and the local counts are reported separately** and are never mixed into one number.
* **No merge.** PR #12 stays open; the merge blocker of the reviewer (the commit-by-commit ancestry explanation and the minimal/reconciled diff plan) is not part of this iteration.

---

## 7. Files touched

| file | change |
| --- | --- |
| `modal_app.py` | the fixed production producer: no `modal.running_app()`, explicit `NOT_AVAILABLE` with precise reasons, every fact names its side |
| `benchmarks/evidence_integrity.py` | the sides of an observation, the typed facts with an optional side, the side rule of the envelope schema, the side in the stage facts |
| `benchmarks/adapters.py` | the client-side observation of the provider-issued app id and app page URL |
| `benchmarks/run_iteration20_producer_capture.py` | the local capture of the real producer |
| `benchmarks/validate_iteration20_evidence.py` | the validator: the producer source, the capture from disk, the repository validators, the code-SHA binding |
| `benchmarks/evidence/iteration20_producer_capture/` | the artifacts of the capture (the stage evidence artifact and the capture record) |
| `benchmarks/evidence/iteration20_validation_evidence.json` | the published validation artifact, bound to the code SHA |
| `benchmarks/evidence/iteration20_change_impact_matrix.md` | this matrix |
| `tests/test_iteration20_evidence_integrity.py` | the focused test suite |
| `.github/workflows/ci.yml` | run the Iteration 20 suite and the Iteration 20 validator |

---

## 8. Results of this iteration

The local counts and the CI counts are reported **separately** and are never mixed into one number.

### 8.1 The commits of this iteration

| commit | content |
| --- | --- |
| `cce5d61` | this matrix — committed **before** any code change |
| `64392a7` | the fix of the production producer, the contract of the observation side, the client-side observation, the capture, the validator, the test suite, the CI wiring |
| `2b73f24` | the capture of the producer and the validation report, bound to `64392a7` |

The report is bound to the **code commit** `64392a7` — the commit the capture was made from — and `64392a7` is an ancestor of `HEAD`.

### 8.2 The capture of the producer

| item | value |
| --- | --- |
| exact command | `python -m benchmarks.run_iteration20_producer_capture --code-sha 64392a7…` |
| source commit | `64392a7bc4d4eba45a0fc15aacd4b32e3761dd98` (tracked files clean) |
| Modal SDK | 1.5.5 (the installed SDK; the producer was executed against it) |
| producer | the **real** `modal_app.capture_modal_runtime_identity()` |
| sentinel | `modal.running_app` was replaced by a hostile sentinel for the duration of the call — **0 accesses** |
| container environment | `MODAL_WORKER_ID` and `HOSTNAME` removed, as in a Modal function container |
| invocation | `live_modal_invocation: false`, `deployment: none`, `gpu: none` |
| app id | **NOT_AVAILABLE** — Modal SDK 1.5.5 exposes no running-app accessor to a function container |
| app page URL | **NOT_AVAILABLE** — the only candidate was the unsupported `modal.running_app` |
| container id | **NOT_AVAILABLE** — neither `MODAL_WORKER_ID` nor `HOSTNAME` |
| function-call id | **NOT_AVAILABLE** — `modal.current_function_call_id()` returns no id outside a Modal function container |
| provider-issued identifiers in the capture | **none** — the capture is local, so it holds no `ap-…`, no `fc-…` and no `ta-…` |

Artifacts on disk:

| artifact | SHA-256 |
| --- | --- |
| `benchmarks/evidence/iteration20_producer_capture/ITER20-01_stage_evidence_evm_sandbox.json` | `cdf0653f5f16a6e8174da65ac37073f7e5f8cf69dffdbffa3a742175f3934820` |
| `benchmarks/evidence/iteration20_producer_capture/capture_record.json` | `e00cb729b5eff35d83ed38c028b45863e3ab4e5eccc7e40c2ff7cee28c6f980d` |

### 8.3 The validator

`python -m benchmarks.validate_iteration20_evidence --code-sha 64392a7bc4d4eba45a0fc15aacd4b32e3761dd98`
→ **PASSED, 12/12 checks**:

| check | what it proves |
| --- | --- |
| `P2.1.producer_source_has_no_running_app_call` | the parsed syntax tree of the producer contains no call of `modal.running_app` |
| `P2.2.no_live_invocation_and_no_deployment` | the capture declares no live invocation, no deployment, no GPU and states the production-change boundary |
| `P2.3.sentinel_never_touched` | the sentinel was never touched |
| `P2.4.envelope_is_typed_and_worker_side` | every identity fact is a typed fact that names the worker side, and the envelope satisfies the unchanged Iteration 18 schema |
| `P2.5.app_id_is_an_explicit_absence` | the application id is `NOT_AVAILABLE` with the exact reason of the producer and holds no value |
| `P2.6.app_page_url_is_an_explicit_absence` | the app page URL is `NOT_AVAILABLE` with the exact reason of the producer and holds no value |
| `P2.7.container_id_is_an_explicit_absence` | the container id is `NOT_AVAILABLE` with the exact reason of the producer and holds no value |
| `P2.8.client_observation_is_client_side` | the client-side facts name the client side and the worker envelope holds no client-side fact |
| `P2.9.artifact_digest_matches_the_bytes_on_disk` | the SHA-256 of the artifact on disk equals the recorded digest |
| `P2.10.stage_evidence_artifact_satisfies_the_contract` | the artifact satisfies the unchanged Iteration 18 contract and carries exactly the envelope of the captured response |
| `P2.11.stage_facts_keep_the_side_of_the_envelope` | the derived stage facts keep the side the envelope declared |
| `P2.12.capture_is_bound_to_its_code_sha` | the capture names the commit it was made from |

`python -m benchmarks.validate_iteration20_evidence --check` → published PASSED, revalidated PASSED (12/12), bound to `64392a7`.

### 8.4 The local run (Windows, this machine)

| suite | result |
| --- | --- |
| Iteration 20 (`tests/test_iteration20_evidence_integrity.py`) | **33 passed**, 0 skipped |
| Iteration 19 | 24 passed |
| Iteration 18 | 44 passed |
| Iteration 17 | 65 passed |
| Iteration 16 | 27 passed |
| Iteration 15 | 33 passed |
| Iteration 14 | 73 passed, 3 skipped (the real-Foundry probes: `forge` is not on the local PATH) |
| full suite `tests/` | **684 passed, 7 skipped** (95.62 s) |

The 7 local skips are exactly the pre-existing ones of Iterations 14 and the benchmark execution suite — **none of them belongs to the Iteration 20 suite**:

1. `tests/test_iteration14_evidence_integrity.py::test_real_foundry_integration_observed_environment_carries_real_facts`
2. `tests/test_iteration14_evidence_integrity.py::test_real_foundry_integration_safe_control_emits_the_exact_documented_sentinel`
3. `tests/test_iteration14_evidence_integrity.py::test_real_foundry_integration_compilation_error_is_never_a_safe_control`
4. `tests/test_real_benchmark_execution.py::test_real_slither_integration_is_not_run_when_binary_missing`
5. `tests/test_real_benchmark_execution.py::test_real_foundry_integration_live_execution`
6. `tests/test_real_benchmark_execution.py::test_real_foundry_integration_confirmed_exploit_breach`
7. `tests/test_real_benchmark_execution.py::test_real_foundry_integration_compilation_failure`

`forge` and `slither` are **not installed on this machine**, so the real Foundry probes are skipped locally. The Foundry numbers are therefore taken from the CI job `foundry-integration` and are reported as CI numbers — they are never mixed with the local ones.

### 8.5 The CI run

CI run [`42790479610`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42790479610) of the branch (`3780d63`) — **green**. These are **CI** numbers; they are never mixed with the local numbers above.

| step | result |
| --- | --- |
| Iteration 20 suite (`tests/test_iteration20_evidence_integrity.py`) | **33 passed** |
| complete test suite | **680 passed, 11 skipped** (9.37 s) |
| Foundry EVM integration (`tests/test_real_benchmark_execution.py -k real_foundry`) | **4 passed** |
| Foundry EVM integration (`tests/test_iteration14_evidence_integrity.py -k real_foundry`) | **3 passed** |
| `python -m benchmarks.validate_iteration20_evidence --check` | published PASSED, revalidated PASSED (**12/12**), bound to `64392a7` |
| `python -m benchmarks.validate_iteration19_evidence --check` | published PASSED, revalidated PASSED (**12/12**), bound to `18ad974` |
| Iterations 14–18 benchmark validation | still **FAILED (0/16 targets)** — the CI reports it explicitly, the green workflow does not mask it |

The 11 CI skips are the pre-existing ones: four `solc` compile probes of the contract normalization suite and the seven Foundry/slither probes that the CI runs in the separate `foundry-integration` job (where they pass: 4 + 3). **None of them belongs to the Iteration 20 suite.**

The CI count grew by exactly the 33 tests of the new suite: 647 passed + 33 = 680 passed, with the same 11 skips as before.


