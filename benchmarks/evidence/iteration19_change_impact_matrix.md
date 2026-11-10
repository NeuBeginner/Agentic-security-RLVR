# Iteration 19 — Change Impact Matrix

**Iteration:** 19 (PR #12 follow-up)
**Scope:** live Modal **CPU-only** runtime smoke test — prove that a real Modal worker is invoked and that it returns worker-observed runtime evidence, and persist that evidence under the Iteration 18 contract.
**Trigger:** independent review comment [`issuecomment-6755862371`](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/12#issuecomment-6755862371) (2026-11-10).
**Authorization:** the project owner explicitly authorized a real Modal **CPU-only** test on 2026-11-10. The authorization covers CPU-only execution only: **no H100, no T4, no other GPU, no model loading or inference, no paid GPU benchmark, and no change to any deployed production worker.**

---

## 1. Why this iteration exists

Iterations 14–18 hardened the evidence chain of the benchmark run:

| iteration | what it proved |
| --- | --- |
| 14 | provider-issued identifiers instead of hardcoded ones; `NOT_AVAILABLE` instead of silent fillers; billing split into app/session level and target level |
| 15 | every `NOT_AVAILABLE` fact points at a digest-verifiable artifact; the producer and the validator share one classifier |
| 16 | every stage has an artifact of its own; a fact may only cite the artifact of its own stage |
| 17 | the four flags of a stage form a state machine; the kind of absence follows from the state |
| 18 | the flag, the stored payload and the runtime-identity envelope describe one event and may not contradict each other |

Every published validation artifact up to now was nevertheless produced **offline**: the "producer rehearsal" of Iteration 16–18 executes the real producer path against faithful reconstructions of worker responses, and the historical 16-target run on disk predates the per-stage artifacts altogether. A rehearsal is a rehearsal — it can prove that the *contract* holds, but it cannot prove that a **real Modal worker** exists, is reached, and reports its own runtime identity.

Iteration 19 closes exactly that gap, with the smallest possible live surface: **one CPU-only function, one invocation, one artifact.**

---

## 2. Scope and authorization boundaries

| allowed | forbidden |
| --- | --- |
| a separate, minimal CPU-only Modal app and function | any GPU (`gpu=None`, no GPU option at all) |
| one invocation, CPU-only, bounded timeout | H100 / T4 / any GPU allocation |
| a small deterministic payload + a runtime envelope | model loading, model inference, any model download |
| the worker-observed OS / Python / runtime metadata | a persistent volume, a mounted model cache |
| reading the workspace billing report of the CPU-only run | any call into an existing GPU-backed method or production class |
| a new evidence artifact + a new validator + a new test suite | changing `main`, PR #8, the integration branch, or any deployed worker |
| | merging PR #12 |

**Stop conditions.** If the Modal credentials are unavailable, the app cannot be invoked, or any step would require a GPU, a production deployment or a broader spend, the iteration stops and reports the blocker. There is no fallback to a local execution: a local run would be a rehearsal, and a rehearsal is never reported as a live pass.

---

## 3. Design

### 3.1 A separate, minimal, CPU-only app

`benchmarks/modal_cpu_smoke_app.py` is an app of its own. It does not import `modal_app.py`, does not instantiate a production class and does not touch a GPU-backed method. Its single function is declared as:

```python
@app.function(gpu=None, cpu=0.5, memory=256, timeout=60, retries=0)
```

`gpu=None` is explicit, the runtime is 60 s, the memory request is 256 MiB, and the retry count is 0 — one invocation, no loop. The image is `debian_slim` plus **one** mounted file: the repository's own `benchmarks/evidence_integrity.py`. No secrets, no volumes, no model.

### 3.2 The worker builds the envelope with the repository's own primitives

The mounted module is the repository's real evidence module, so the envelope the worker returns is built by the same code the validator later checks — not by a re-implementation that could drift. The worker observes exactly what the existing workers observe (`modal_app.py::capture_modal_runtime_identity`):

| fact | source inside the container |
| --- | --- |
| `app_id` | `modal.running_app().app_id` |
| `function_call_id` | `modal.current_function_call_id()` |
| `container_id` | `MODAL_WORKER_ID` (fallback `HOSTNAME`) |

Every value is **provider-issued**: no identifier is derived from a configured name. The envelope is a typed-fact object — `OBSERVED` with a named source, or `NOT_AVAILABLE` with an explicit reason.

### 3.3 The client captures the response verbatim and writes per-stage evidence

`benchmarks/run_iteration19_cpu_smoke.py` invokes the function exactly once and stores the returned object **unchanged** as the captured response. The runtime-identity envelope is the value the captured response carries at the declared source `modal_runtime` — the same binding the Iteration 18 validator enforces. The capture is then written with the repository's own producer:

```python
write_stage_evidence_artifact(directory, capture, target_id="CPU-SMOKE-01", correlation_id=...)
```

A contradictory capture is refused by the producer (`EvidenceContractError`) instead of being written down; a failed invocation is recorded as the honest state `ATTEMPT_FAILED_NO_RESPONSE` — never as a success.

### 3.4 The validator re-reads the artifact from disk

`benchmarks/validate_iteration19_evidence.py` does not trust the producer. It re-reads the bytes from disk, recomputes the SHA-256, compares it with the digest the invocation record claims, and then runs the repository validators over the artifact:

* `validate_stage_evidence_artifact(payload, expected_stage="cpu_smoke")` — the Iteration 18 validator;
* `validate_runtime_identity_envelope(payload["runtime_identity"])` — the Iteration 18 envelope schema;
* the state table of Iteration 17 for the four flags;
* the provider-issued identifier shapes of Iteration 14.

The published report is bound to the exact code SHA it was produced from, and `--check` refuses a report that is bound to a foreign SHA.

### 3.5 What is observed and what is `NOT_AVAILABLE`

A fact is either `OBSERVED` (with the source it was read from) or `NOT_AVAILABLE` (with the exact reason it could not be observed). There is no third state, and in particular **no field is filled in from a template, a guess or a constant**.

| field | how it is obtained |
| --- | --- |
| app id, function-call id, container id | provider-issued, observed inside the container |
| image identity | `MODAL_IMAGE_ID` of the running container (an immutable `im-…` id) |
| image **digest** | `NOT_AVAILABLE` — Modal SDK 1.5.5 exposes no image-digest API to the container (the CLI offers only `modal image names` and `modal image logs`) |
| session id | `NOT_AVAILABLE` — the Modal SDK 1.5.5 contains no session-id accessor (`modal.running_app()` exposes `app_id`, `app_page_url`, `app_logs_url`, `function_ids`, `class_ids`, `object_handle_metadata`, `interactive`) |
| billed CPU / runtime usage | the provider's own workspace billing report; `NOT_AVAILABLE` with the exact provider error when the workspace exposes no such report — never an estimate |
| worker Python / OS / Modal SDK version | observed inside the container |
| zero-GPU proof | worker-observed: no `NVIDIA_VISIBLE_DEVICES`, no `CUDA_VISIBLE_DEVICES`, no `/dev/nvidia*` node, no `nvidia-smi`, no CUDA runtime library |

---

## 4. Change Impact Matrix

| # | Requirement | Producer (evidence is created here) | Captured response | Runtime envelope | Validator / report | Accepted when | Positive test | Negative (adversarial) tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | A real Modal worker is invoked — not a rehearsal | `benchmarks/run_iteration19_cpu_smoke.py` calls the function of a separate CPU-only app exactly once | the response the worker returned | the envelope the worker built | the invocation record names the invocation status and the provider-issued identifiers | the invocation status is `SUCCEEDED` and the response is present | `test_iteration19_the_invocation_record_reports_a_successful_single_invocation` | `test_iteration19_a_failed_invocation_is_recorded_as_a_failed_stage` |
| 2 | The app is CPU-only and isolated | `benchmarks/modal_cpu_smoke_app.py` (`gpu=None`, `cpu=0.5`, `memory=256`, `timeout=60`, `retries=0`, no volume, no secret, no model) | — | — | the invocation record states the declared resources; the worker-observed GPU evidence is empty | the declared resources carry no GPU and the worker observed no GPU device | `test_iteration19_the_app_declares_no_gpu_and_the_worker_observed_no_gpu_device` | `test_iteration19_a_gpu_allocation_is_rejected` |
| 3 | The identifiers are provider-issued, not inferred from names | the worker reads `modal.running_app().app_id`, `modal.current_function_call_id()`, `MODAL_WORKER_ID` | — | `app_id`, `function_call_id`, `container_id` | the validator checks the provider shapes (`ap-…`, `fc-…`, worker id) and rejects the synthetic container ids | every identifier matches its provider shape | `test_iteration19_the_observed_identifiers_match_the_provider_shapes` | `test_iteration19_a_synthetic_container_id_is_rejected` |
| 4 | The response is captured verbatim and the envelope is the one it carries | `write_stage_evidence_artifact` (the Iteration 18 producer) | the unchanged return value of the worker | the value at the declared source `modal_runtime` | `validate_stage_evidence_artifact` + the canonical-JSON equality of the envelope | `provider_response["modal_runtime"] == runtime_identity` | `test_iteration19_the_envelope_is_the_one_the_captured_response_carries` | `test_iteration19_a_detached_envelope_is_rejected` |
| 5 | The four flags describe exactly one state | the producer writes the flags of the capture | — | — | the state table of Iteration 17 | the state is `EXECUTED_WITH_RUNTIME_ENVELOPE` | `test_iteration19_the_smoke_stage_is_in_the_state_with_a_runtime_envelope` | `test_iteration19_an_impossible_state_is_rejected` |
| 6 | Every identity fact is a documented typed fact | the worker builds `OBSERVED` / `NOT_AVAILABLE` facts with the repository's own primitives | — | `validate_runtime_identity_envelope` | the validator runs the envelope schema | every identity field is `OBSERVED` with a source, or `NOT_AVAILABLE` with a reason | `test_iteration19_the_envelope_carries_typed_facts_only` | `test_iteration19_a_malformed_identity_fact_is_rejected` |
| 7 | The artifact digest is verified from disk | the invocation record stores the path and the SHA-256 of the written artifact | — | — | the validator recomputes the digest of the bytes on disk | the recomputed digest equals the recorded digest | `test_iteration19_the_artifact_digest_matches_the_bytes_on_disk` | `test_iteration19_a_tampered_artifact_is_rejected` |
| 8 | The evidence is bound to the code that produced it | the driver records the source commit SHA and the dirty state of the tracked files | — | — | the published report is bound to that SHA; `--check` refuses a foreign SHA | the bound SHA is an ancestor of `HEAD` | `test_iteration19_the_validation_evidence_is_bound_to_the_code_sha` | `test_iteration19_the_check_mode_detects_a_foreign_code_sha` |
| 9 | The runtime metadata is worker-observed | the worker reports its Python, OS, Modal SDK version and image identity | — | — | the validator checks the presence of the worker-observed fields and the explicit `NOT_AVAILABLE` reasons | the fields are observed or explicitly unavailable | `test_iteration19_the_worker_observed_runtime_metadata_is_recorded` | `test_iteration19_an_unexplained_missing_field_is_rejected` |
| 10 | The billed usage is real or explicitly unavailable | the driver asks the provider's workspace billing report | — | — | the invocation record carries the provider value or a `NOT_AVAILABLE` fact with the exact provider reason | the value is provider-issued or explicitly unavailable — never estimated | `test_iteration19_the_billed_usage_is_provider_backed_or_explicitly_unavailable` | `test_iteration19_an_estimated_billed_usage_is_rejected` |
| 11 | No production deployment and no change to the deployed workers | the driver creates an ephemeral app of its own | — | — | the invocation record states the deployment kind and the untouched production surface | the app is ephemeral and no production worker was touched | `test_iteration19_the_run_declares_an_ephemeral_app_and_no_production_change` | — |
| 12 | The new suite and the new validator run in CI | `.github/workflows/ci.yml` | — | — | the workflow references both | the workflow runs both | `test_iteration19_the_ci_workflow_runs_the_new_suite_and_the_new_validator` | — |

---

## 5. The exact API of this iteration

| symbol | module | role |
| --- | --- | --- |
| `cpu_smoke` | `benchmarks/modal_cpu_smoke_app.py` | the single CPU-only function of the smoke app |
| `main` | `benchmarks/run_iteration19_cpu_smoke.py` | one invocation, the capture, the artifact and the invocation record |
| `validate_iteration19` | `benchmarks/validate_iteration19_evidence.py` | re-reads the artifact from disk and runs the repository validators |
| `write_stage_evidence_artifact` | `benchmarks/evidence_integrity.py` | the unchanged Iteration 18 producer |
| `validate_stage_evidence_artifact` | `benchmarks/evidence_integrity.py` | the unchanged Iteration 18 artifact validator |
| `validate_runtime_identity_envelope` | `benchmarks/evidence_integrity.py` | the unchanged Iteration 18 envelope schema |

Nothing in `benchmarks/evidence_integrity.py` is changed by this iteration. The iteration adds a runtime, a producer, a validator and a suite — it does not weaken a single existing assertion.

---

## 6. Honest boundaries of this iteration

* **This is not a benchmark validation.** The 16-target run on disk still fails the Iteration 16–18 validators; this iteration does not change that, and it does not claim otherwise.
* **One function, one invocation, CPU-only.** No GPU was allocated, no model was loaded, no deployed worker was changed, and no production deployment was made or modified.
* **The smoke test is not the 16-target benchmark.** A green smoke test proves that a real Modal worker is reached and reports its own identity. It says nothing about the quality of the sixteen benchmark targets.
* **The CI counts and the local counts are reported separately** and are never mixed into one number.
* **The billed usage is never estimated.** If the provider exposes no billing line for the run, the report says `NOT_AVAILABLE` with the exact provider reason.
* **A local run is never reported as a live pass.** If the invocation fails, the artifact records the failure and the validator reports `FAILED`.

---

## 7. Files touched

| file | change |
| --- | --- |
| `benchmarks/modal_cpu_smoke_app.py` | the separate, minimal CPU-only Modal app and its single function |
| `benchmarks/run_iteration19_cpu_smoke.py` | one invocation, the capture, the per-stage evidence artifact and the invocation record |
| `benchmarks/validate_iteration19_evidence.py` | the fresh-state validator: digest from disk + the repository validators + the code-SHA binding |
| `benchmarks/evidence/iteration19_cpu_smoke/` | the artifacts of the live run (the stage evidence artifact and the invocation record) |
| `benchmarks/evidence/iteration19_validation_evidence.json` | the published validation artifact, bound to the code SHA |
| `benchmarks/evidence/iteration19_change_impact_matrix.md` | this matrix |
| `tests/test_iteration19_evidence_integrity.py` | the focused test suite |
| `.github/workflows/ci.yml` | run the Iteration 19 suite and the Iteration 19 validator |

---

## 8. Results of this iteration

*Pending — this section is completed with the actual numbers after the live run and the focused test run. The local run and the CI run are reported separately and are never mixed into one number.*
