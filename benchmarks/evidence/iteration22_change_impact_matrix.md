# Iteration 22 — Change Impact Matrix

**Iteration:** 22 (PR #12 follow-up)
**Scope:** the **strict** provenance validation must require the **observation side** of every observed identity fact — in the evidence contract (`benchmarks/evidence_integrity.py`), in the strict provenance consumer and in the validators.
**Trigger:** independent review comment [`issuecomment-676333330`](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/12#issuecomment-6765333330) (2026-11-10).
**Authorization:** **no live Modal call is required**. No deployment, no redeployment, no restart, no modification of any live worker, no GPU (H100/T4), no paid GPU work, no production change.

---

## 1. Why this iteration exists

The Iteration 21 review was **NOT ACCEPTED**: the provider-backed container identity was accepted, but a **narrow validator gap** in `benchmarks/evidence_integrity.py` was kept open as a P1.

> `validate_runtime_identity_envelope(..., strict_sources=True)` calls `validate_observation_side()` and then `validate_provider_observation_source()`. Both currently accept an `OBSERVED` fact with no `observed_by` field:
>
> * `validate_observation_side()` explicitly returns success when `observed_by` is absent.
> * `validate_provider_observation_source()` also checks the side only when it is non-null.
>
> Consequently, a worker fact with the registered source `modal.current_function_call_id()`, a valid `fc-…` value, but **no observation-side declaration** passes strict validation.

The defect is narrow and precise, and this iteration is about exactly that narrow defect:

* the **producer** is not the problem — `modal_app.py::capture_modal_runtime_identity()` names the side of every fact it writes (`observed_by="worker"`), and the facts derived from the envelope (`build_stage_identity_facts`) carry the side the envelope declared;
* the **contract** is the problem — the strict mode accepts an observed value that names **no** side at all, although the closed source/side registry of Iteration 21 says which side each field may be observed from.

So the fix is in the **validator**, not in the producer: in strict mode an observed identity fact must name the side that observed it, and that side must be the one registered for the field.

---

## 2. The confirmed defect, exactly as it stands

### 2.1 The two helpers that let it through

| helper | current behaviour | why it is wrong in the strict mode |
| --- | --- | --- |
| `validate_observation_side(fact, expected_side=…)` | `declared = fact.get("observed_by")`; **`if declared is None: return True, None`** — a fact that names no side is accepted | the strict mode is supposed to be the mode in which every observed fact names its side; the early return makes the omission invisible |
| `validate_provider_observation_source(field_name, fact, expected_side=…)` | `declared = fact.get("observed_by")`; the side is compared with the registered side **only** `if declared is not None` | a fact with the *registered source* and the *registered shape* but **no** side is accepted, so the registry of source↔side is never enforced |

### 2.2 The concrete hole

A worker envelope with this fact passes `validate_runtime_identity_envelope(envelope, strict_sources=True)` **today**:

```json
{
  "function_call_id": {
    "status": "OBSERVED",
    "value": "fc-abc123",
    "source": "modal.current_function_call_id() (Modal SDK 1.5.5, inside the running container)"
  }
}
```

The value has the provider's shape (`fc-…`), the source is the **registered** worker-side source of `function_call_id` — and the fact does not say **who** observed it. The same hole exists for the client-side fields `app_id`, `app_page_url` and `container_id`, whose registered source is a client-side source: a fact with that source, a valid `ap-…` / `https://modal.com/id/ap-…` / `ta-…` value and no side passes the strict mode as well.

The consequence is exactly the ambiguity the closed registry of Iteration 21 was built to remove: **the registry knows which side may observe a field, but the strict mode does not make the fact name that side.** A worker-side envelope can therefore carry a client-side observation without declaring it, and a reader of the artifact cannot tell from the fact itself which side produced the value.

### 2.3 Why the compatibility reason does not apply here

The reason the side-less fact is accepted today is backward compatibility: every artifact of Iterations 14–19 has no `observed_by` at all. That reason is valid — **for the compatibility path**. It is not valid for the strict mode, which exists precisely to state the *new*, stricter contract. The two must be separated:

* the **compatibility path** (the default, `strict_sources=False`) stays exactly as it is — side-less facts stay valid, no artifact of Iterations 14–20 is invalidated;
* the **strict path** (`strict_sources=True`) requires the side of every observed identity fact and requires it to be the registered one.

---

## 3. Scope and authorization boundaries

| allowed | forbidden |
| --- | --- |
| the shared evidence contract in `benchmarks/evidence_integrity.py` | any `modal deploy`, redeploy, restart or modification of a live worker |
| a new validator (`benchmarks/validate_iteration22_evidence.py`), a new focused test suite (`tests/test_iteration22_evidence_integrity.py`) | any GPU (H100 / T4 / any other), any model loading, any paid GPU work |
| the validation evidence of this iteration, bound to its own code SHA | any live Modal invocation (not required for this iteration) |
| running the focused tests, the Iterations 14–21 suites, the full regression suite, the Foundry integration and CI | merging PR #12, touching `main`, PR #8 or the integration branch |
| re-reading the artifacts of Iterations 14–21 from disk in the **non-strict** compatibility path | changing the producer (`modal_app.py`) — it is not the defect, and it already names the side of every fact |

**Stop conditions.** If the fix would require a deployment, a live worker, a GPU or a paid resource, the iteration stops and reports the blocker instead of weakening a validator or a test.

---

## 4. Design

### 4.1 The rule

> In the strict mode, an `OBSERVED` identity fact must **name** the side that observed it, and that side must be **exactly** the side registered for the field in `PROVIDER_OBSERVATION_SOURCES`.

Four cases are rejected in the strict mode, for **every** observed identity fact:

| case | example | rejected because |
| --- | --- | --- |
| **missing** | `observed_by` absent | the fact does not name the side that observed it |
| **null** | `observed_by: null` | identical to missing — `fact.get("observed_by")` yields `None` |
| **unknown** | `observed_by: "oracle"` | a fact may name only a known side (`worker`, `client`) |
| **contradictory** | `observed_by: "client"` on the worker-side `function_call_id`, or `observed_by: "worker"` on the client-side `app_id` | the declared side contradicts the side registered for the field (and, inside a worker envelope, the side of the envelope itself) |

### 4.2 The change in the contract

`benchmarks/evidence_integrity.py` gets **three additive** changes — no signature is broken, no default changes, no existing assertion is weakened:

| # | place | change |
| --- | --- | --- |
| 1 | `validate_observation_side(fact, *, expected_side=None, require_side=False)` | new keyword `require_side`: when it is set, a fact that names **no** side is rejected instead of accepted. The keyword defaults to `False`, so the compatibility path is untouched |
| 2 | `validate_provider_observation_source(field_name, fact, *, expected_side=None, require_side=False)` | new keyword `require_side`: when it is set, the side must be **present**, **known** and **exactly the registered side** of the field; the existing "check the side only when it is non-null" is replaced by the strict comparison |
| 3 | `validate_runtime_identity_envelope(..., strict_sources=True)` and `validate_client_observed_facts(..., strict_sources=True)` | pass `require_side=True` to the helpers |
| 4 | `validate_modal_invocation_provenance(..., strict_sources=True)` | the strict provenance consumer now applies the **same** rule to the **stage** facts of the worker — the facts that reach a reader as `modal_invocation_provenance.stages.<stage>.<field>`. This is what makes the fix observable at the level a reader of an artifact actually sees |

The `NOT_AVAILABLE` facts are **not** affected: a fact that holds no value was observed by nobody and names no side — the facts of Iterations 14–21 do not carry a side on them, and the requirement of this iteration is scoped to `OBSERVED` facts. The scope of the rule is stated here so that it is not silently widened later.

### 4.3 The strict provenance consumer

The consumer is `validate_modal_invocation_provenance(artifact, *, known_app_ids=…, evidence_root=…, strict_sources=True)`. It is the function that decides whether an artifact may be published, and it is what the Iteration 21 capture is validated with (`P3.12`).

In the strict mode it now checks, in addition to everything it already checked:

* every **stage** fact that is `OBSERVED` names its side, and the side is the registered one for that field (`function_call_id` → worker, `app_id` / `app_page_url` / `container_id` → client);
* every **stage** fact is a **typed fact** — a legacy flat value (a bare string) names no side and is therefore not acceptable in the strict mode. The legacy flat shape stays valid in the compatibility path, which is where the artifacts of Iterations 14–20 are read;
* the **client block** keeps its own, unchanged rule: every client fact must name the client side (it always did).

### 4.4 The compatibility path stays open

The artifacts of Iterations 14–20 are read through the **non-strict** path and remain valid:

| artifact | path | result |
| --- | --- | --- |
| the artifacts of Iterations 14–19 | `validate_modal_invocation_provenance(artifact)` (no `strict_sources`) | unchanged — the side-less facts of that era stay valid |
| the capture of Iteration 20 | `validate_iteration20_evidence.py` (unchanged) | unchanged |
| the capture of Iteration 21 | `validate_iteration21_evidence.py` (unchanged) | unchanged — the producer already named the side of every fact, so the capture satisfies the stricter rule as well |

**No side is ever inferred or backfilled.** The compatibility path does not guess the side of an old fact and does not write one into the artifact; it simply accepts the old shape, and only there. The strict path never accepts it.

---

## 5. The vertical chains that are affected

| requirement | producer → typed fact → validator → consumer | what changes |
| --- | --- | --- |
| every observed identity fact names its side | `modal_app.py::capture_modal_runtime_identity` → `observed(…, observed_by="worker")` → `validate_observation_side` / `validate_provider_observation_source` → `validate_runtime_identity_envelope` → `validate_modal_invocation_provenance` | the **validator** stops accepting a side-less observed fact in the strict mode; the producer already writes the side |
| the side is the registered one | `PROVIDER_OBSERVATION_SOURCES` (source ↔ side ↔ shape) → `validate_provider_observation_source` → `validate_runtime_identity_envelope` → `validate_modal_invocation_provenance` | the registered side is now compared **unconditionally** in the strict mode, not only when a side happens to be present |
| the worker envelope may not carry a client observation | worker envelope → `validate_observation_side(expected_side="worker")` → `validate_runtime_identity_envelope` → the strict consumer | unchanged in substance; the strict mode now also catches the side-less variant of the same defect |
| the client block is client-side | client block → `validate_client_observed_facts` → `validate_modal_invocation_provenance` | unchanged — the client block always required the client side |
| the artifacts of Iterations 14–20 stay readable | the artifacts on disk → the **non-strict** validators → the compatibility path | unchanged — no default behaviour changed |
| the evidence of this iteration | the Iteration 21 producer capture (the producer is unchanged) + the adversarial probes → `benchmarks/validate_iteration22_evidence.py` → the report `benchmarks/evidence/iteration22_validation_evidence.json` | new — the report is bound to the code SHA of this iteration |

---

## 6. The evidence of this iteration

The producer is **not** changed by this iteration, so no new live capture is needed — and none is made. The evidence of Iteration 22 is:

1. the **Iteration 21 producer capture**, read again from disk: the digest of its stage evidence artifact is recomputed and compared with the digest the capture record claims, the producer source is compared with the commit the capture was made from (byte-identical — the producer did not change), and the capture is validated in the **new** strict mode;
2. the **adversarial probes**: the validator is run against facts that omit the side, name it as `null`, name an unknown side or name the wrong side — for the worker field `function_call_id` and for the client fields `app_id`, `app_page_url` and `container_id` — and every one of them has to be **rejected**, while the valid worker and client facts have to be **accepted**;
3. the **compatibility probe**: the artifacts of Iterations 14–21 are read through the non-strict path and have to stay **valid**;
4. the **consumer probe**: the strict provenance consumer itself (`validate_modal_invocation_provenance(..., strict_sources=True)`) is run against a tampered artifact whose digests were **recomputed**, so the rejection can only come from the missing side and not from a stale digest.

The report is bound to the exact code SHA of this iteration, and `--check` refuses a foreign SHA.

---

## 7. The tests that must exist

`tests/test_iteration22_evidence_integrity.py`:

| # | test | what it proves |
| --- | --- | --- |
| 1 | worker `function_call_id` with the correct source and a valid `fc-…` value but **no** `observed_by` | rejected in the strict mode |
| 2 | the same omission for the client fields `app_id`, `app_page_url` and `container_id` | rejected in the strict mode |
| 3 | `observed_by: null`, `observed_by: "oracle"` and the wrong side (client on a worker field, worker on a client field) | rejected in the strict mode |
| 4 | valid worker and client facts | still accepted in the strict mode |
| 5 | side-less artifacts of Iterations 14–21 | still accepted **only** through the non-strict compatibility path |
| 6 | the strict provenance consumer against a tampered artifact with **recomputed** digests | the consumer rejects the omission itself — not a stale digest |
| 7 | the artifacts on disk of Iterations 14–21 | still valid through the compatibility path |

---

## 8. What this iteration does **not** claim

* It does not claim a live Modal validation: no invocation is made, the provider is never asked, no worker is deployed and no deployed worker is touched.
* It does not change the historical benchmark result: the 16-target run on disk still fails the Iteration 16–18 validators, and this iteration does not change that and does not claim otherwise.
* It does not weaken the compatibility path to make a new test pass: the strict mode is stricter, the compatibility path is unchanged.
* It does not merge PR #12 and does not touch `main`, PR #8 or the integration branch.

---

## 9. The results of this iteration

### 9.1 The commits

| | SHA | content |
| --- | --- | --- |
| Change impact matrix | `e77b896` | this document, **before** any code change |
| **Code** | **`f0ce026`** | the fix of the strict observation side, the validator of the iteration, the focused test suite, the two CI steps |
| Validation evidence | `bb50ac6` | `benchmarks/evidence/iteration22_validation_evidence.json`, bound to `f0ce026` |
| Completed matrix | `c72c6a9` | this document with the local and the CI numbers |

The validation evidence is bound to the exact code SHA `f0ce026d446e2c69a87f2bb4c155dcf0d36cd58b` (field `code_sha`). `python -m benchmarks.validate_iteration22_evidence --check` re-validates the report against that commit and refuses a foreign SHA.

### 9.2 The validator

```
$ python -m benchmarks.validate_iteration22_evidence --code-sha f0ce026d446e2c69a87f2bb4c155dcf0d36cd58b
wrote benchmarks/evidence/iteration22_validation_evidence.json: PASSED, 11/11 checks passed

$ python -m benchmarks.validate_iteration22_evidence --check
validation report benchmarks/evidence/iteration22_validation_evidence.json: published PASSED, revalidated PASSED (11/11 checks), bound to f0ce026d446e2c69a87f2bb4c155dcf0d36cd58b
```

| check | what it proves |
| --- | --- |
| `P4.1.the_strict_mode_rejects_an_observed_fact_without_a_side` | the omission is rejected for the worker field and for every client field |
| `P4.2.null_unknown_and_contradictory_sides_are_rejected` | the null, the unknown and the contradictory side are rejected |
| `P4.3.the_strict_mode_accepts_the_valid_facts` | the valid worker fact, the valid client facts and the client block are accepted |
| `P4.4.the_compatibility_path_still_accepts_a_side_less_fact` | the side-less fact stays valid — no side is inferred, none is backfilled |
| `P4.5.the_strict_consumer_rejects_the_omission_with_recomputed_digests` | the **actual** strict provenance consumer rejects the omission while the digests are recomputed from the bytes on disk, and accepts the very same artifact once the side is back |
| `P4.6.the_published_capture_passes_the_strict_mode` | the published capture of Iteration 21 still passes the strict mode |
| `P4.7.the_producer_source_is_unchanged_since_the_capture` | the producer source is byte-wise unchanged between `40c0630` (the commit the capture was made from) and the reported commit — the capture is still the capture of this producer |
| `P4.8.the_artifact_digest_is_the_digest_of_the_bytes_on_disk` | the SHA-256 of the stage evidence artifact is the digest of the bytes on disk |
| `P4.9.the_historical_evidence_stays_valid` | the evidence of Iterations 20 and 21 still satisfies its own validator |
| `P4.10.no_live_invocation_no_provider_query_no_deployment_and_no_gpu` | the boundary of the iteration |
| `P4.11.the_pre_fix_rule_reproduces_the_defect` | the rule of Iteration 21 — the side is compared only when the fact names one — is reproduced inside the validator and **still accepts** the omission: the defect was real and the checks are not vacuous |

### 9.3 The local test runs — exact raw counts

Focused Iteration 22 suite:

```
$ python -m pytest -q tests/test_iteration22_evidence_integrity.py
28 passed in 0.40s
```

The suites of the earlier iterations, unchanged:

| suite | result |
| --- | --- |
| `tests/test_iteration14_evidence_integrity.py` | 73 passed, 3 skipped in 0.34s |
| `tests/test_iteration15_evidence_integrity.py` | 33 passed in 0.18s |
| `tests/test_iteration16_evidence_integrity.py` | 27 passed in 23.02s |
| `tests/test_iteration17_evidence_integrity.py` | 65 passed in 0.17s |
| `tests/test_iteration18_evidence_integrity.py` | 44 passed in 8.47s |
| `tests/test_iteration19_evidence_integrity.py` | 24 passed in 0.34s |
| `tests/test_iteration20_evidence_integrity.py` | 33 passed in 0.48s |
| `tests/test_iteration21_evidence_integrity.py` | 41 passed in 0.50s |

Full regression, **without** `forge` on `PATH`:

```
$ python -m pytest -q tests/ -rs
753 passed, 7 skipped in 108.59s (0:01:48)
```

(the skips are the real-Foundry and real-Slither probes — `forge` was not on `PATH` in that shell)

Full regression, **with** the real Foundry toolchain (`forge 1.9.0`, commit `6056c5845d34205a83cf7108042adb137325c9df`, solc `0.8.20`, `forge-std v1.9.5`, `openzeppelin-contracts v5.0.2`, `FOUNDRY_CI=true`):

```
$ python -m pytest -q tests/ -rs
759 passed, 1 skipped in 150.41s (0:02:30)
```

(the only skip is the real Slither probe — `slither` is not installed on this machine)

Real Foundry EVM integration (positive and negative):

```
$ python -m pytest -v -rA tests/test_real_benchmark_execution.py -k "test_real_foundry_integration"
PASSED tests/test_real_benchmark_execution.py::test_real_foundry_integration_live_execution
PASSED tests/test_real_benchmark_execution.py::test_real_foundry_integration_confirmed_exploit_breach
PASSED tests/test_real_benchmark_execution.py::test_real_foundry_integration_compilation_failure
PASSED tests/test_real_benchmark_execution.py::test_real_foundry_integration_is_not_run_when_binary_missing
4 passed, 65 deselected in 9.27s

$ python -m pytest -v -rA tests/test_iteration14_evidence_integrity.py -k "real_foundry"
PASSED tests/test_iteration14_evidence_integrity.py::test_real_foundry_integration_observed_environment_carries_real_facts
PASSED tests/test_iteration14_evidence_integrity.py::test_real_foundry_integration_safe_control_emits_the_exact_documented_sentinel
PASSED tests/test_iteration14_evidence_integrity.py::test_real_foundry_integration_compilation_error_is_never_a_safe_control
3 passed, 73 deselected in 4.20s
```

### 9.4 The CI run — these are CI numbers, never mixed with the local ones

CI run [`42806453926`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42806453926) (head `c72c6a9`) is **green**:

| step | result |
| --- | --- |
| Iteration 22 suite | **28 passed** |
| Iteration 21 / 20 / 19 / 18 / 17 / 16 / 15 suites | 41 / 33 / 24 / 44 / 65 / 27 / 33 passed |
| Iteration 14 suite | 73 passed, 3 skipped |
| trusted evidence and reward contract tests | 58 / 25 passed, 23 passed 4 skipped |
| GRPO and trajectory integrity tests | 6 / 5 / 5 / 6 passed |
| complete test suite | **749 passed, 11 skipped** |
| Foundry EVM integration (`test_real_benchmark_execution.py -k real_foundry`) | **4 passed** |
| Foundry EVM integration (`test_iteration14_evidence_integrity.py -k real_foundry`) | **3 passed** |
| `validate_iteration22_evidence --check` | published PASSED, revalidated PASSED (**11/11**), bound to `f0ce026` |
| `validate_iteration21_evidence --check` | published PASSED, revalidated PASSED (**13/13**), bound to `40c0630` |
| `validate_iteration20_evidence --check` | published PASSED, revalidated PASSED (**12/12**), bound to `64392a7` |
| `validate_iteration19_evidence --check` | published PASSED, revalidated PASSED (**12/12**), bound to `18ad974` |
| Iterations 14–18 benchmark validation | still **FAILED (0/16 targets)** — reported by the CI, not masked by the green workflow |

The CI count grew by exactly the 28 new tests (721 + 28 = 749 passed) with the same 11 skips as the run before.

### 9.5 What the numbers are and what they are not

The local numbers above are the numbers of **this machine**: a Windows host with the repository's own Foundry toolchain (`forge 1.9.0`) and the pre-baked `solc 0.8.20`. The CI numbers are the numbers of the Linux runner of GitHub Actions. The two are never mixed: the local run has fewer skips (the real Foundry probes run here) and the CI run has the Slither probe skipped as well.

The benchmark result of the 16-target run stays **FAILED** (0/16 targets): this iteration does not change it and does not claim otherwise.
