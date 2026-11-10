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

The review asks for the ancestry to be re-measured against the current head before any merge. Measured at the reviewed head `5e17910d5a99a196cf5fa16268792d3a71d265e2` (base `736f11d` = `integration/minimax-antigravity-reconciled`):

| measurement | value |
| --- | --- |
| commits ahead of the PR base | **72** |
| merge base of base and head | `736f11d` (the base itself — the branch is a fast-forward of the base) |
| diff against the PR base (`736f11d...5e17910`) | **256 files changed, +83,331 / −357** |
| the Issue-mandated branch base | `47e49b9` (the tip of the upstream line `feat/empirical-benchmark-runner`) |
| commits of the upstream line `736f11d..47e49b9` | **32** |
| commits of the iteration work `47e49b9..5e17910` | **40** |
| diff against the mandated base (`47e49b9...5e17910`) | **84 files changed, +35,369 / −1,258** |

The 32 commits of the upstream line are **not** contained in the integration branch (`47e49b9` is not an ancestor of `736f11d`), which is why the diff against the PR base carries the whole upstream line as well.

The 40 commits of the iteration work touch **10 files** that the upstream line also touched:

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

**Consequence for the merge plan.** A clean rebase of the 40 iteration commits onto `736f11d` does **not** apply: those 10 files are rewritten by both lines. The reconciled plan is therefore:

1. merge the upstream line `736f11d..47e49b9` into `integration/minimax-antigravity-reconciled` **first** — it is the Issue-mandated base and it is not contained in the integration branch today;
2. after that, the diff of PR #12 shrinks from 256 files to the **84 files** of the iteration work, and the conflicts are confined to the 10 files above;
3. resolve those 10 files by hand, keeping the upstream behaviour where the two lines do not touch the same hunk, and the evidence contract of Iterations 14–23 where they do.

No merge of PR #12 is performed by this iteration.

---

## 11. The results of this iteration

*(filled in after the code, the evidence and the CI run — the local numbers and the CI numbers are reported separately and are never mixed)*
