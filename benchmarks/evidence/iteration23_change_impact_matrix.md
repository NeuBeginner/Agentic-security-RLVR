# Iteration 23 — Change Impact Matrix

**Iteration:** 23 (PR #12 follow-up)
**Scope:** the **strict** stage validation must take the observation side from the **registered** source of the field — in the evidence contract (`benchmarks/evidence_integrity.py`) and in the strict provenance consumer.
**Trigger:** independent review comment [`issuecomment-6766255520`](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/12#issuecomment-6766255520) (2026-11-10).
**Authorization:** **no live Modal call is required**. No deployment, no redeployment, no restart, no modification of any live worker, no GPU (H100/T4), no paid GPU work, no production change.

---

## 1. Why this iteration exists

The Iteration 22 review was **NOT ACCEPTED**: the mandatory observation side was implemented, but one **narrow validator gap** in the strict stage validation was kept open as a P1.

> In `validate_modal_invocation_provenance(..., strict_sources=True)`, the stage-fact loop currently calls
>
> ```python
> validate_provider_observation_source(
>     key,
>     fact,
>     expected_side=OBSERVATION_SIDE_WORKER,
>     require_side=True,
> )
> ```
>
> for **every** key in `PROVIDER_OBSERVATION_SOURCES`.
>
> But the registry defines:
> - `function_call_id` → worker;
> - `app_id`, `app_page_url`, `container_id` → client.
>
> Therefore the strict stage validator hardcodes `expected_side="worker"` even for fields whose only registered provider source is client-side. A correctly typed, correctly sourced client-side `OBSERVED app_id` / `container_id` stage fact is rejected as contradictory.

The defect is narrow and precise, and this iteration is about exactly that narrow defect:

* the **producer** is not the problem — `modal_app.py::capture_modal_runtime_identity()` names the side of every fact it writes (`observed_by="worker"`), and the facts derived from the envelope (`build_stage_identity_facts`) carry the side the envelope declared;
* the **registry** is not the problem — `PROVIDER_OBSERVATION_SOURCES` already states, per field, which side may observe it;
* the **consumer** is the problem — the strict stage loop overrides the registry with a hardcoded `worker` side.

So the fix is in the **validator**, not in the producer and not in the registry.

---

## 2. The confirmed defect, exactly as it stands

### 2.1 The one line that is wrong

`benchmarks/evidence_integrity.py`, in the strict branch of `validate_modal_invocation_provenance()`:

| place | current code | why it is wrong |
| --- | --- | --- |
| the strict stage loop | `validate_provider_observation_source(key, fact, expected_side=OBSERVATION_SIDE_WORKER, require_side=True)` for **every** `key` in `PROVIDER_OBSERVATION_SOURCES` | the side of a fact is not a property of the *stage*, it is a property of the *field*. `app_id`, `app_page_url` and `container_id` are registered as client-side fields, so a stage fact that names the client side for them is **correct**, and the consumer rejects it as contradictory |

### 2.2 The registry the consumer contradicts

| field | registered source | registered side | shape |
| --- | --- | --- | --- |
| `function_call_id` | `modal.current_function_call_id()` | **worker** | `fc-…` |
| `app_id` | the provider-issued `App.app_id` of the running app (client side) | **client** | `ap-…` |
| `app_page_url` | `App.get_dashboard_url()` (client side) | **client** | `https://modal.com/id/ap-…` |
| `container_id` | the provider's call graph + container listing (client side) | **client** | `ta-…` |

`require_side=True` already compares the declared side with the **registered** side of the field and rejects a contradiction. The additional `expected_side=OBSERVATION_SIDE_WORKER` therefore adds nothing for the worker field and **breaks** the three client fields: for them the registered comparison passes and the hardcoded comparison fails.

### 2.3 The concrete hole

A stage of a provenance block with these facts is **correctly typed, correctly sourced and correctly sided** — and the strict consumer rejects it today:

```json
{
  "app_id":        {"status": "OBSERVED", "value": "ap-gW7GDdh9OlSqjL2tRnB1oJ",
                    "source": "the provider-issued App.app_id of the running app (Modal SDK 1.5.5, client side)",
                    "observed_by": "client"},
  "function_call_id": {"status": "OBSERVED", "value": "fc-01M71H7789CATYCWNEG05916Y3",
                    "source": "modal.current_function_call_id()",
                    "observed_by": "worker"},
  "container_id":  {"status": "OBSERVED", "value": "ta-01M71H78SAWD0JF71CFPA0QTRR",
                    "source": "the provider's call graph (FunctionCall.get_call_graph) and container listing (TaskList) of Modal SDK 1.5.5, client side",
                    "observed_by": "client"}
}
```

The error the consumer returns is the envelope rule (`"this envelope is 'worker'-side"`) applied to a field whose registered side is the client side — a rule that belongs to the **runtime-identity envelope** of the worker, not to a stage.

### 2.4 Why the compatibility reason does not apply here

The strict mode is **not** the compatibility path. The compatibility path (the default, `strict_sources=False`) reads the artifacts of Iterations 14–20 and stays exactly as it is. The strict mode exists to state the new, stricter contract, and the stricter contract of Iteration 21/22 is the **registry**: one source, one side, one shape per field. The strict stage consumer has to apply that registry, not a hardcoded side.

---

## 3. Scope and authorization boundaries

| allowed | forbidden |
| --- | --- |
| the shared evidence contract in `benchmarks/evidence_integrity.py` | any `modal deploy`, redeploy, restart or modification of a live worker |
| a new validator (`benchmarks/validate_iteration23_evidence.py`), a new focused test suite (`tests/test_iteration23_evidence_integrity.py`) | any GPU (H100 / T4 / any other), any model loading, any paid GPU work |
| the validation evidence of this iteration, bound to its own code SHA | any live Modal invocation (not required for this iteration) |
| running the focused tests, the Iterations 14–22 suites, the full regression suite, the Foundry integration and CI | merging PR #12, touching `main`, PR #8 or the integration branch |
| re-reading the artifacts of Iterations 14–22 from disk in the **non-strict** compatibility path | changing the producer (`modal_app.py`) — it is not the defect, and it already names the side of every fact |

**Stop conditions.** If the fix would require a deployment, a live worker, a GPU or a paid resource, the iteration stops and reports the blocker instead of weakening a validator or a test.

---

## 4. Design

### 4.1 The rule

> In the strict stage validation, the side of a fact is the side **registered for that field** in `PROVIDER_OBSERVATION_SOURCES`. A stage is not worker-side by construction: it is a record of the observations of one stage, and every observation names its own side.

The rule that is **preserved** and stays separate:

> A **worker runtime-identity envelope** is worker-side by construction — a client observation may never be presented inside it. This is enforced by `validate_runtime_identity_envelope(..., expected_side="worker")` and is **not** touched by this iteration.

### 4.2 The change in the contract

`benchmarks/evidence_integrity.py` gets **one** change — a single call site, no signature is broken, no default changes, no existing assertion is weakened:

| # | place | change |
| --- | --- | --- |
| 1 | the strict stage loop of `validate_modal_invocation_provenance(..., strict_sources=True)` | the expected side is taken from the registry — `PROVIDER_OBSERVATION_SOURCES[key]["side"]` — instead of the hardcoded `OBSERVATION_SIDE_WORKER` |

Everything else is unchanged:

| rule | place | state |
| --- | --- | --- |
| the side of an observed fact has to be **present**, **known** and **exactly the registered one** | `validate_provider_observation_source(..., require_side=True)` | unchanged (Iteration 22) |
| a **worker envelope** may not claim a client observation | `validate_observation_side(..., expected_side="worker")` via `validate_runtime_identity_envelope` | unchanged (Iteration 20/22) |
| the **client block** is client-side | `validate_client_observed_facts` | unchanged (Iterations 20/21) |
| a legacy flat value names no side and is refused in the strict mode | the strict stage loop | unchanged (Iteration 22) |
| the compatibility path reads the side-less artifacts of Iterations 14–20 | `strict_sources=False` | unchanged |

### 4.3 What the fix does **not** do

* it does **not** accept a client observation for the **worker** field: `function_call_id` is registered as worker-side, so a stage fact that names the client side for it stays rejected — by the registered comparison of Iteration 22 and, independently, by the envelope rule;
* it does **not** accept a worker observation for a **client** field: `app_id`, `app_page_url` and `container_id` are registered as client-side, so a stage fact that names the worker side for them stays rejected as contradictory — the smuggling direction stays closed;
* it does **not** accept a fact that names **no** side, an **unknown** side, a **non-registered** source or a value of the wrong **shape**;
* it does **not** change the producer, the registry, the envelope rule, the client-block rule or the compatibility path.

### 4.4 The compatibility path stays open

| artifact | path | result |
| --- | --- | --- |
| the artifacts of Iterations 14–20 | `validate_modal_invocation_provenance(artifact)` (no `strict_sources`) | unchanged |
| the capture of Iteration 20 | `validate_iteration20_evidence.py` (unchanged) | unchanged |
| the capture of Iteration 21 | `validate_iteration21_evidence.py` (unchanged) | unchanged |
| the report of Iteration 22 | `validate_iteration22_evidence.py` (unchanged) | unchanged |

**No side is ever inferred or backfilled.**

---

## 5. The vertical chains that are affected

| requirement | producer → typed fact → validator → consumer | what changes |
| --- | --- | --- |
| the side of a stage fact is the registered side of the field | `modal_app.py::capture_modal_runtime_identity` / the client block → `observed(…, observed_by=…)` → `PROVIDER_OBSERVATION_SOURCES` → `validate_provider_observation_source` → `validate_modal_invocation_provenance` | the consumer stops overriding the registry with a hardcoded `worker` side |
| a worker envelope may not carry a client observation | worker envelope → `validate_observation_side(expected_side="worker")` → `validate_runtime_identity_envelope` → the strict consumer | unchanged — the rule stays and is proven by its own test |
| a client field may not be presented as a worker observation | the registry → the registered-side comparison of Iteration 22 → the strict stage loop | unchanged — the smuggling direction stays closed |
| the client block is client-side | client block → `validate_client_observed_facts` → `validate_modal_invocation_provenance` | unchanged |
| the artifacts of Iterations 14–22 stay readable | the artifacts on disk → the **non-strict** validators → the compatibility path | unchanged |
| the evidence of this iteration | the Iteration 21 producer capture (the producer is unchanged) + the adversarial probes → `benchmarks/validate_iteration23_evidence.py` → the report `benchmarks/evidence/iteration23_validation_evidence.json` | new — the report is bound to the code SHA of this iteration |

---

## 6. The evidence of this iteration

The producer is **not** changed by this iteration, so no new live capture is needed — and none is made. The evidence of Iteration 23 is:

1. the **Iteration 21 producer capture**, read again from disk: the digest of its stage evidence artifact is recomputed and compared with the digest the capture record claims, the producer source is compared with the commit the capture was made from (byte-identical — the producer did not change), and the capture is validated in the **current** strict mode;
2. the **adversarial probes** against the **actual** strict consumer (`validate_modal_invocation_provenance(..., strict_sources=True)`):
   * a **positive** probe — a stage with a worker-observed `function_call_id` and client-observed `app_id`, `app_page_url` and `container_id` is **accepted**;
   * the **negative** probes — the same facts with a **missing**, a **null**, an **unknown** and the **wrong** side are **rejected**; a worker-side claim on a client field is **rejected**; a client-side claim on the worker field is **rejected**;
   * the **envelope** probe — a worker runtime-identity envelope that carries a client observation is **rejected** (the separate rule);
   * the **digest** probe — the tampered artifact has its digests **recomputed** from the bytes on disk, so a rejection can only come from the side rule and not from a stale digest;
3. the **compatibility probe**: the artifacts of Iterations 14–22 are read through the non-strict path and have to stay **valid**;
4. the **reproduction probe**: the rule of Iteration 22 (the hardcoded `worker` side for every registered field) is reproduced inside the validator and still **rejects** the correctly sided client fact — the defect was real, and the checks are not vacuous.

The report is bound to the exact code SHA of this iteration, and `--check` refuses a foreign SHA.

---

## 7. The tests that must exist

`tests/test_iteration23_evidence_integrity.py`:

| # | test | what it proves |
| --- | --- | --- |
| 1 | the strict consumer accepts a stage with a worker-observed `function_call_id` | the worker field still works |
| 2 | the strict consumer accepts a stage with a client-observed `app_id`, `app_page_url` and `container_id` | the defect is closed — the registered side is honoured |
| 3 | the same facts with a **missing**, a **null**, an **unknown** side | rejected |
| 4 | the same facts with the **wrong** side (worker on a client field, client on the worker field) | rejected — the cross-side direction stays closed |
| 5 | a worker runtime-identity envelope that carries a client observation | rejected — the separate envelope rule is preserved |
| 6 | the tampered artifact with **recomputed** digests | the rejection comes from the side rule, not from a stale digest |
| 7 | the producer → stage facts → serialized artifact → strict consumer chain | the whole path holds |
| 8 | the artifacts of Iterations 14–22 | still valid through the compatibility path |

---

## 8. What this iteration does **not** claim

* It does not claim a live Modal validation: no invocation is made, the provider is never asked, no worker is deployed and no deployed worker is touched.
* It does not change the historical benchmark result: the 16-target run on disk still fails the Iteration 16–18 validators, and this iteration does not change that and does not claim otherwise.
* It does not weaken the compatibility path to make a new test pass: the strict mode gets *more* precise, the compatibility path is unchanged.
* It does not merge PR #12 and does not touch `main`, PR #8 or the integration branch.

---

## 9. Known limitation, deliberately **not** closed by this iteration

The run-level fact `modal_invocation_provenance.modal_app_id` is checked by the strict consumer **only** in its `NOT_AVAILABLE` shape (the evidence reference has to be the one of the EVM sandbox stage). An `OBSERVED` run-level application id is not side-checked by the consumer today.

This is a **separate, wider** question than the P1 of this iteration: it concerns a *run-level* fact, not the stage facts, and closing it would change the contract of a field that the producer fills with the fact of the EVM sandbox stage. It is therefore **recorded here and not changed** — it is stated so that it is not silently forgotten, and it is explicitly **not** claimed to be closed.

---

## 10. The ancestry of the branch — refreshed against the reviewed head

The review asks for the ancestry to be re-measured against the current head before any merge.

**Measured at the reviewed head `5e17910d5a99a196cf5fa16268792d3a71d265e2`** (base `736f11d` = `integration/minimax-antigravity-reconciled`):

| measurement | value |
| --- | --- |
| commits ahead of the PR base | **72** |
| merge base of base and head | `736f11d` (the base itself — the branch is a fast-forward of the base) |
| diff against the PR base (`736f11d...5e17910`) | **256 files changed, +83,331 / −357** |
| the Issue-mandated branch base | `47e49b9` (the tip of the upstream line `feat/empirical-benchmark-runner`) |
| commits of the upstream line `736f11d..47e49b9` | **32** |
| commits of the iteration work `47e49b9..5e17910` | **40** |
| diff against the mandated base (`47e49b9...5e17910`) | **84 files changed, +35,369 / −1,258** |

**Measured at the head of this iteration `1e5a1bc7de39036e38a5d1306f43c5ca3a235995`** (the three commits of Iteration 23 added):

| measurement | value |
| --- | --- |
| commits ahead of the PR base | **75** |
| diff against the PR base (`736f11d...1e5a1bc`) | **260 files changed, +86,062 / −357** |
| commits of the iteration work `47e49b9..1e5a1bc` | **43** |
| diff against the mandated base (`47e49b9...1e5a1bc`) | **88 files changed, +38,100 / −1,258** |

The 32 commits of the upstream line are **not** contained in the integration branch (`47e49b9` is not an ancestor of `736f11d`), which is why the diff against the PR base carries the whole upstream line as well.

The 43 commits of the iteration work touch **10 files** that the upstream line also touched:

```
.github/workflows/ci.yml
.gitignore
benchmarks/adapters.py
benchmarks/benchmark_runner.py
benchmarks/evidence/modal_billing_join_table.json
benchmarks/protocol.py
core/schemas.py
modal_app.py
sandbox/runner.py
tests/test_real_benchmark_execution.py
```

**Consequence for the merge plan.** A clean rebase of the 43 iteration commits onto `736f11d` does **not** apply: those 10 files are rewritten by both lines. The reconciled plan is therefore:

1. merge the upstream line `736f11d..47e49b9` into `integration/minimax-antigravity-reconciled` **first** — it is the Issue-mandated base and it is not contained in the integration branch today;
2. after that, the diff of PR #12 shrinks from 260 files to the **88 files** of the iteration work, and the conflicts are confined to the 10 files above;
3. resolve those 10 files by hand, keeping the upstream behaviour where the two lines do not touch the same hunk, and the evidence contract of Iterations 14–23 where they do.

The three commits of Iteration 23 themselves touch **4 files** and none of the 10 contested ones except the CI workflow:

| commit | files |
| --- | --- |
| `73de47e` (the matrix) | `benchmarks/evidence/iteration23_change_impact_matrix.md` |
| `749cba2` (the code) | `benchmarks/evidence_integrity.py`, `benchmarks/validate_iteration23_evidence.py`, `tests/test_iteration23_evidence_integrity.py`, `.github/workflows/ci.yml` |
| `1e5a1bc` (the evidence) | `benchmarks/evidence/iteration23_validation_evidence.json` |

No merge of PR #12 is performed by this iteration.

---

## 11. The results of this iteration

### 11.1 The commits

| | SHA | content |
| --- | --- | --- |
| Change impact matrix | `73de47e` | this document, **before** any code change |
| **Code** | **`749cba2`** | the fix of the registered observation side, the validator of the iteration, the focused test suite, the two CI steps |
| Validation evidence | `1e5a1bc` | `benchmarks/evidence/iteration23_validation_evidence.json`, bound to `749cba2` |
| Completed matrix | *(this commit)* | this document with the local and the CI numbers |

The validation evidence is bound to the exact code SHA `749cba244b58fd76a3b91efe46df0c6bac204af6` (field `code_sha`). `python -m benchmarks.validate_iteration23_evidence --check` re-validates the report against that commit and refuses a foreign SHA.

### 11.2 The validator

```
$ python -m benchmarks.validate_iteration23_evidence --code-sha 749cba244b58fd76a3b91efe46df0c6bac204af6
wrote benchmarks/evidence/iteration23_validation_evidence.json: PASSED, 12/12 checks passed

$ python -m benchmarks.validate_iteration23_evidence --check
validation report benchmarks/evidence/iteration23_validation_evidence.json: published PASSED, revalidated PASSED (12/12 checks), bound to 749cba244b58fd76a3b91efe46df0c6bac204af6
```

| check | what it proves |
| --- | --- |
| `P5.1.the_strict_consumer_accepts_the_registered_side_of_every_field` | the worker field and every client field are accepted with their **own** registered side |
| `P5.2.the_missing_null_and_unknown_side_are_rejected` | the missing, the null and the unknown side are rejected for every registered field |
| `P5.3.the_cross_side_direction_stays_closed` | a client field may not be presented as a worker observation, and the worker field may not be presented as a client observation |
| `P5.4.a_worker_envelope_may_not_carry_a_client_observation` | the separate rule of the worker runtime-identity envelope is preserved |
| `P5.5.the_rejection_comes_from_the_side_rule_and_not_from_a_stale_digest` | the artifact is rewritten, the digests are recomputed from the bytes on disk, and the wrong side is refused by the side rule |
| `P5.6.the_published_capture_passes_the_strict_mode` | the published capture of Iteration 21 still passes the strict mode |
| `P5.7.the_producer_source_is_unchanged_since_the_capture` | the producer source is byte-wise unchanged between `40c0630` (the commit the capture was made from) and the reported commit |
| `P5.8.the_artifact_digest_is_the_digest_of_the_bytes_on_disk` | the SHA-256 of the stage evidence artifact is the digest of the bytes on disk |
| `P5.9.the_historical_evidence_stays_valid` | the evidence of Iterations 20, 21 and 22 still satisfies its own validator |
| `P5.10.no_live_invocation_no_provider_query_no_deployment_and_no_gpu` | the boundary of the iteration |
| `P5.11.the_pre_fix_rule_reproduces_the_defect` | the rule of Iteration 22 — the expected side of a stage fact is hardcoded to `worker` — is reproduced inside the validator and still rejects the correctly sided client fact: the defect was real and the checks are not vacuous |
| `P5.12.the_compatibility_path_still_accepts_the_side_less_facts` | the side-less facts of Iterations 14–20 stay valid — no side is inferred and none is backfilled |

### 11.3 The local test runs — exact raw counts

The machine that produced these numbers has **no Foundry toolchain on `PATH`** (`forge` is not installed; the local Foundry directory is empty), so the real Foundry integration is **not** part of the local numbers — it is part of the CI numbers in §11.4.

Focused Iteration 23 suite:

```
$ python -m pytest -q tests/test_iteration23_evidence_integrity.py
34 passed in 0.47s
```

The suites of the earlier iterations, unchanged:

| suite | result |
| --- | --- |
| `tests/test_iteration14_evidence_integrity.py` | 73 passed, 3 skipped in 0.30s |
| `tests/test_iteration15_evidence_integrity.py` | 33 passed in 0.15s |
| `tests/test_iteration16_evidence_integrity.py` | 27 passed in 17.97s |
| `tests/test_iteration17_evidence_integrity.py` | 65 passed in 0.16s |
| `tests/test_iteration18_evidence_integrity.py` | 44 passed in 7.24s |
| `tests/test_iteration19_evidence_integrity.py` | 24 passed in 0.33s |
| `tests/test_iteration20_evidence_integrity.py` | 33 passed in 0.42s |
| `tests/test_iteration21_evidence_integrity.py` | 41 passed in 0.46s |
| `tests/test_iteration22_evidence_integrity.py` | 28 passed in 0.40s |

Full regression, **without** `forge` on `PATH`:

```
$ python -m pytest -q tests/ -rs
787 passed, 7 skipped in 102.31s (0:01:42)
```

(the skips are the real-Foundry and real-Slither probes — `forge` and `slither` are not on `PATH` in that shell). The count grew by exactly the 34 new tests of this iteration: 753 + 34 = 787.

**The checks are not vacuous.** With the fix reverted, the new suite fails 7 of its 34 tests — every positive probe of the defect fails, including the digest-recomputed chain:

```
$ # the contract of Iteration 22 is restored (the expected side of a stage fact
$ # is hardcoded to 'worker' again) and the suite is run unchanged
$ python -m pytest -q tests/test_iteration23_evidence_integrity.py
FAILED tests/test_iteration23_evidence_integrity.py::test_iteration23_the_strict_consumer_accepts_a_client_observed_app_id_in_a_stage
FAILED tests/test_iteration23_evidence_integrity.py::test_iteration23_the_strict_consumer_accepts_a_client_observed_container_id_in_a_stage
FAILED tests/test_iteration23_evidence_integrity.py::test_iteration23_the_strict_consumer_accepts_a_client_observed_app_page_url_in_a_stage
FAILED tests/test_iteration23_evidence_integrity.py::test_iteration23_the_registry_is_the_single_source_of_truth_for_the_stage_side
FAILED tests/test_iteration23_evidence_integrity.py::test_iteration23_the_strict_consumer_accepts_a_client_observed_app_id_with_the_billing_cross_check
FAILED tests/test_iteration23_evidence_integrity.py::test_iteration23_the_client_side_facts_are_accepted_with_recomputed_digests
FAILED tests/test_iteration23_evidence_integrity.py::test_iteration23_the_strict_consumer_rejects_the_wrong_side_with_recomputed_digests
7 failed, 27 passed in 0.60s
```

The pre-fix error is the envelope rule applied to a stage fact:

```
AssertionError: The fact for 'app_id' declares the observation side 'client', but this envelope is 'worker'-side
```

### 11.4 The CI run — these are CI numbers, never mixed with the local ones

CI run [`42810765129`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42810765129) (head `1e5a1bc`) is **green** — both jobs:

| job | result |
| --- | --- |
| Reward v2 and trusted harness regression suite | success |
| Real Foundry EVM integration probe | success |

The numbers of the **raw workflow log**:

| step | result |
| --- | --- |
| trusted evidence and reward contract tests | 58 passed / 25 passed / 23 passed, 4 skipped |
| Iteration 23 suite | **34 passed** |
| Iteration 22 / 21 / 20 / 19 / 18 / 17 / 16 / 15 suites | 28 / 41 / 33 / 24 / 44 / 65 / 27 / 33 passed |
| Iteration 14 suite | 73 passed, 3 skipped |
| GRPO and trajectory integrity tests | 6 / 5 / 5 / 6 passed |
| complete test suite | **783 passed, 11 skipped** |
| real Foundry EVM integration (`tests/test_real_benchmark_execution.py -k test_real_foundry_integration`) | **4 passed**, 65 deselected |
| real Foundry probes of Iteration 14 (`-k real_foundry`) | **3 passed**, 73 deselected |

Foundry in CI: `forge Version: 1.9.1-nightly`, commit `5745b69600a557aec7e6f4598ccfa1efc64b6add`.

The **evidence validators of the earlier iterations** in the same run:

| validator | result |
| --- | --- |
| Iteration 14 | `FAILED (0/16 targets)`, bound to `43436b02…` — the historical benchmark result, unchanged |
| Iteration 15 | `FAILED (0/16 targets)`, bound to `cf262236…` |
| Iteration 16 | `FAILED (0/16 targets)`, bound to `b1946536…` |
| Iteration 17 | `FAILED (0/16 targets)`, bound to `e9faff40…` |
| Iteration 18 | `FAILED (0/16 targets)`, bound to `8813cebd…` |
| Iteration 19 | published PASSED, revalidated PASSED (12/12), bound to `18ad9740…` |
| Iteration 20 | published PASSED, revalidated PASSED (12/12), bound to `64392a7b…` |
| Iteration 21 | published PASSED, revalidated PASSED (13/13), bound to `40c06309…` |
| Iteration 22 | published PASSED, revalidated PASSED (11/11), bound to `f0ce026d…` |
| **Iteration 23** | **published PASSED, revalidated PASSED (12/12), bound to `749cba24…`** |

The raw log of the run shows the command of this iteration explicitly — the claim is not inferred:

```
Real Foundry EVM integration probe	Validate Iteration 23 registered observation side
validation report benchmarks/evidence/iteration23_validation_evidence.json: published PASSED, revalidated PASSED (12/12 checks), bound to 749cba244b58fd76a3b91efe46df0c6bac204af6
```

The benchmark result of the 16-target run stays **FAILED (0/16 targets)**: this iteration does not change it and does not claim otherwise.

The **final** CI run of the head of this iteration is [`42811416769`](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/42811416769) (head `19ad672`, the completed matrix) — **green** as well, with the same numbers in the raw log: the Iteration 23 suite **34 passed**, the complete suite **783 passed, 11 skipped**, the real Foundry EVM integration **4 passed**, the Iteration 14 Foundry probes **3 passed**, and the validator of this iteration again

```
validation report benchmarks/evidence/iteration23_validation_evidence.json: published PASSED, revalidated PASSED (12/12 checks), bound to 749cba244b58fd76a3b91efe46df0c6bac204af6
```

### 11.5 The boundary of this iteration

No live Modal invocation, no provider query, no deployment, no redeployment, no restart, no modification of a live worker, no GPU (H100/T4 or any other), no paid compute. The `OBSERVED` branch of the producer was exercised in a **simulated** container context (a patched `modal.current_function_call_id`) and is called a simulation wherever it is mentioned. `main`, PR #8 and the integration branch are untouched, and PR #12 is **not** merged.

