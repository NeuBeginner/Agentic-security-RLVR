# Iteration 18 — Change Impact Matrix

**Iteration:** 18 (PR #12 follow-up)
**Scope:** P0.1 — bind the captured response to the runtime envelope: the flag, the stored payload and the runtime-identity envelope must describe the same thing, in both directions.
**Trigger:** independent review comment `issuecomment-6752627516` (2026-11-09).

---

## 1. The defect this iteration removes

Iteration 17 closed the state machine of a stage: the four flags describe
exactly one state, every state allows exactly the kinds of absence that can
honestly occur in it, and the producer and the validator share one classifier.
An independent review of the final validator found three remaining ways for an
internally self-consistent, SHA-256-valid artifact to misrepresent what the
stage actually returned.

### Finding 1 — a response can be stored while the state says no response

`validate_stage_evidence_artifact()` rejects `response_received=True` with
`provider_response is None`, but not the inverse: `response_received=False`
while `provider_response` holds a non-null payload. The state table can
therefore say `ATTEMPT_FAILED_NO_RESPONSE` while the artifact also stores a
provider response. The digest of that payload can be recomputed, so the hash
check does not catch the contradiction — the artifact is consistent with
itself and wrong about the stage.

The response metadata has the same gap: it always carries a digest, a byte
length and a source, so a stage that received no response still looks like a
stage whose response was captured and hashed.

### Finding 2 — a runtime envelope can be detached from the captured response

The check that binds the envelope to the payload is inside

```python
if isinstance(provider_response, dict):
    ...
```

For a payload that is not an object — a string, a list, a scalar — the binding
check is skipped entirely. A self-consistent artifact can therefore carry a
separate runtime-identity envelope and its own digest while the captured
response does not contain that envelope at all.

### Finding 3 — malformed identity fields can be re-labelled as provider omissions

The omission check rejects a field only when its envelope value is an object
with `status == OBSERVED` and a non-null `value`. A malformed representation
such as `{"container_id": "some-id"}` — or an unknown status, or an observed
fact with a null value — is treated as though the provider had simply omitted
the field. The artifact then carries a well-formed `PROVIDER_FIELD_OMITTED`
record about a field the provider *did* answer, in a shape nobody can check.

---

## 2. Design

Iteration 18 binds **three** things together: the flag of the stage, the
payload the artifact stores, and the runtime-identity envelope. They are
descriptions of one event, so they may not contradict each other.

### 2.1 The response and its flag are one thing (Finding 1)

The flag `response_received` and the stored payload are two descriptions of
one fact. Both directions are enforced:

| `response_received` | `provider_response` | response metadata | verdict |
| --- | --- | --- | --- |
| true | not null | digest + length + source, all matching the payload | accepted |
| true | null | — | rejected: a response was received but none is stored |
| false | null | no digest, no length, no source | accepted |
| false | not null | any | rejected: no response was received but one is stored |
| false | null | digest / length / source present | rejected: the metadata implies a response that was never captured |

The producer writes the metadata of a response it actually holds and writes
nothing at all for a stage that received none: no digest of `null`, no byte
length, no source. A digest of the JSON literal `null` is not the digest of a
captured response, and the artifact must not look as if it were.

The modelling has no third state: a provider that answers `null` is recorded as
a stage that returned no response (`response_received=False`). That is what the
client can actually prove, and it is stated instead of guessed.

### 2.2 The envelope belongs to the captured response (Finding 2)

An envelope is never a free-standing object. It is the value the captured
response carries at the declared source:

1. the payload must be an **object** — a string, a list or a scalar payload
   cannot carry an envelope and is therefore rejected, not skipped;
2. the declared `runtime_identity_source` must exist in that payload;
3. the value at that source must be **exactly** the envelope the artifact
   stores (canonical JSON equality, not "looks similar").

The producer enforces the same three rules before it writes anything: it
refuses to store an envelope its payload does not carry. The source is
recorded only when an envelope was received — an artifact that names the
source of an envelope it does not hold is rejected, because a reader would
otherwise have to guess whether the envelope was lost or never existed.

### 2.3 An identity fact is a typed fact or nothing (Finding 3)

Every identity field that the envelope carries must be a **documented typed
fact**:

| status | value | source / reason | verdict |
| --- | --- | --- | --- |
| `OBSERVED` | a non-empty string | a named source | accepted |
| `OBSERVED` | null, a number, an object, an empty string | — | rejected: malformed |
| `NOT_AVAILABLE` | null | an explicit reason | accepted |
| `NOT_AVAILABLE` | any value | — | rejected: malformed |
| anything else | — | — | rejected: unknown status |
| the fact is not an object at all (a bare string, `null`, a list) | — | — | rejected: malformed |

A field that is **present but malformed** is an error. It is never downgraded
to `PROVIDER_FIELD_OMITTED`: the provider did answer, and the artifact must
say that it answered with something that cannot be checked — not that it
answered nothing.

Only the identity fields of the envelope are validated this way. The envelope
the Modal worker returns carries additional provider keys
(`app_page_url`, `container_id_value`) that are not identity fields and are
not classified, so they are not part of this contract.

### 2.4 The producer refuses to write ambiguous evidence

A validator-side check alone would leave the producer able to emit the
ambiguity in the first place. Therefore the producer validates the capture
**before** it writes anything and raises `EvidenceContractError` when the
capture contradicts itself:

* a capture that claims a response but holds no payload;
* a capture that claims no response but holds a payload;
* a capture that holds an envelope but no response;
* a capture whose envelope is not the one its payload carries at the declared
  source;
* a capture whose envelope carries a malformed identity fact.

The adapter turns that error into a **failed target** with an explicit reason
(fail closed, never a silent success and never a misleading artifact).

### 2.5 The evidence wording stays honest

The payload digest remains the digest of the **canonical JSON serialization**
of the stored payload object — never the raw transport bytes the provider put
on the wire. Iteration 18 adds no new wording of that kind: it only decides
*which* payload is hashed (the one that was actually captured, or none at
all).

---

## 3. Change Impact Matrix

| # | Requirement | Producer (evidence is created here) | Captured response | Runtime envelope | Validator / report | Accepted when | Positive test | Negative (adversarial) tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | The response flag and the stored payload are one thing | `build_stage_evidence_artifact` → `_validate_capture` raises `EvidenceContractError` on a contradictory capture | `provider_response` must be non-null exactly when `response_received` is true | — | `validate_stage_evidence_artifact` (both directions) | the flag and the payload agree | `test_iteration18_the_producer_writes_an_artifact_for_an_honest_capture` | `test_iteration18_a_response_may_not_be_stored_next_to_the_no_response_flag`, `test_iteration18_a_response_flag_needs_a_payload`, `test_iteration18_the_producer_refuses_a_contradictory_capture` |
| 2 | The response metadata may not describe a response that was never captured | the producer writes digest + length + source only for a response it holds | — | — | `validate_stage_evidence_artifact` (metadata branch) | no response ⇒ no digest, no length, no source | `test_iteration18_the_producer_writes_no_response_metadata_when_no_response_was_captured` | `test_iteration18_the_response_metadata_may_not_imply_a_response` (digest / length / source) |
| 3 | A captured response must say where it came from | the producer writes `response_source` | — | — | `validate_stage_evidence_artifact` | the source is a non-empty string | `test_iteration18_the_producer_writes_an_artifact_for_an_honest_capture` | `test_iteration18_a_captured_response_needs_its_source` |
| 4 | The envelope must be the one the captured response carries | `_validate_capture` refuses an envelope that is not at the declared source of the payload | the payload must be an object that holds the source | the envelope is compared with the payload value at the source | `validate_stage_evidence_artifact` (envelope branch, for **every** payload shape) | payload[source] == envelope | `test_iteration18_the_honest_four_stage_case_is_accepted` | `test_iteration18_a_fabricated_envelope_next_to_a_non_object_response_is_rejected` (string / list / scalar / bool / number), `test_iteration18_an_envelope_without_its_source_key_is_rejected`, `test_iteration18_a_different_envelope_at_the_source_is_rejected` |
| 5 | The producer may not detach the envelope from the payload | `_validate_capture` raises before anything is written | — | — | — (the artifact is never written) | the capture is refused | `test_iteration18_the_producer_refuses_an_unbound_envelope` | `test_iteration18_the_producer_refuses_an_unbound_envelope` |
| 6 | The source is recorded only when an envelope was received | the producer writes `runtime_identity_source` only for a captured envelope | — | `runtime_identity_source` is empty without an envelope | `validate_stage_evidence_artifact` | source ⇔ envelope | `test_iteration18_the_producer_writes_no_response_metadata_when_no_response_was_captured` | `test_iteration18_an_artifact_may_not_name_the_source_of_an_envelope_it_does_not_hold` |
| 7 | An identity fact must be a documented typed fact | `build_stage_evidence_artifact` / `build_stage_identity_facts` raise `EvidenceContractError` | — | `validate_runtime_identity_envelope` checks every identity field of the envelope | `validate_stage_evidence_artifact` calls the envelope check before any absence record is classified | status, value and source/reason follow §2.3 | `test_iteration18_a_well_formed_fact_is_accepted`, `test_iteration18_a_not_available_fact_is_accepted` | `test_iteration18_a_malformed_identity_fact_is_rejected` (bare string / `null` / list / unknown status / OBSERVED with null / OBSERVED with a number / OBSERVED without a source / NOT_AVAILABLE with a value / NOT_AVAILABLE without a reason) |
| 8 | A malformed field is never re-labelled as a provider omission | the producer refuses to write the artifact | — | the envelope check runs **before** the absence records are classified | `validate_stage_evidence_artifact` (envelope check before the records) | the artifact is rejected, not downgraded | — | `test_iteration18_a_malformed_field_is_not_downgraded_to_a_provider_omission` |
| 9 | The producer and the validator agree on the envelope | `validate_runtime_identity_envelope` is used by both sides | — | one function, one contract | `validate_stage_evidence_artifact` | the producer never writes what the validator rejects | `test_iteration18_the_producer_and_the_validator_agree_about_the_envelope` | `test_iteration18_the_producer_refuses_a_malformed_envelope` |
| 10 | A malformed envelope fails the target closed | `adapters.py` turns `EvidenceContractError` into a FAILED target with an explicit reason | — | — | the run records the failure instead of a misleading artifact | no artifact is written for a broken envelope | `test_iteration18_the_adapter_fails_closed_on_a_malformed_envelope` | `test_iteration18_the_adapter_fails_closed_on_a_malformed_envelope` |
| 11 | The evidence wording stays honest: canonical JSON, not transport bytes | `canonical_json_bytes` computes every payload digest | the digest describes the stored payload object | — | `validate_stage_evidence_artifact` recomputes it | the digest is the digest of the canonical serialization | `test_iteration18_the_artifact_hashes_the_canonical_json_of_the_payload` | `test_iteration18_the_documentation_keeps_the_canonical_distinction` |
| 12 | A fresh validation artifact is published and bound to the code SHA | `benchmarks/validate_iteration18_evidence.py` | the report carries the per-target state of every stage | the report carries the envelope binding per stage | the script itself | the report names the code SHA it was produced from | `test_iteration18_validation_evidence_is_bound_to_the_code_sha` | `test_iteration18_validation_evidence_check_mode_detects_a_foreign_code_sha` |
| 13 | CI runs the new suite and the new validator | `.github/workflows/ci.yml` | — | — | the workflow references both | the workflow runs both | `test_iteration18_ci_workflow_runs_the_new_suite` | — |
| 14 | The producer path is rehearsed offline against faithful worker responses | `benchmarks/validate_iteration18_evidence.py` runs the real producer | the rehearsal captures the same four situations | the rehearsal envelope is the one the workers return | the Iteration 18 validators | the rehearsal passes and every stage shows its own state | `test_iteration18_the_producer_writes_artifacts_the_validator_accepts` | `test_iteration18_every_state_of_the_table_is_accepted` |

---

## 3.1 The exact API of this iteration

| symbol | module | role |
| --- | --- | --- |
| `EvidenceContractError` | `benchmarks/evidence_integrity.py` | raised when the producer is asked to write ambiguous evidence |
| `IDENTITY_FACT_STATUSES` | `benchmarks/evidence_integrity.py` | the documented statuses of a typed fact |
| `validate_runtime_identity_envelope` | `benchmarks/evidence_integrity.py` | the schema of every identity field of an envelope |
| `_validate_capture` | `benchmarks/evidence_integrity.py` | the producer-side contract of a stage capture |
| `validate_stage_evidence_artifact` | `benchmarks/evidence_integrity.py` | the strengthened validator: payload ⇔ flag, envelope ⇔ payload, envelope schema |

---

## 4. Honest boundaries of this iteration

* **No live Modal run, no H100, no paid GPU.** The producer path is exercised
  offline against faithful worker responses; the historical saved run predates
  this fix and is reported as `FAILED` by the validator — that is the honest
  outcome, exactly as in Iterations 15, 16 and 17.
* **The saved 16-target run still fails the new check.** It was produced before
  Iteration 16 gave every stage its own artifact. A green CI workflow is
  **not** a successful 16-target benchmark validation.
* **The CI counts and the local counts are reported separately.** They are
  never mixed into one number.
* **The deployed workers are not changed in this iteration.** The inference and
  the trajectory-persistence stages still return no runtime-identity envelope
  from the workers of today.
* **The billing part of Iteration 15 is not touched.**
* **The Iteration 17 suite is adjusted, not weakened.** Two helpers of
  `tests/test_iteration17_evidence_integrity.py` built artifacts whose payload
  contradicted their own flags (a payload next to `response_received=False`,
  and a digest of the JSON literal `null` for a stage that received no
  response). Both helpers now keep the artifact internally consistent, which
  is what they always claimed to do. No assertion of the Iteration 17 suite is
  removed or relaxed.

---

## 5. Files touched

| file | change |
| --- | --- |
| `benchmarks/evidence_integrity.py` | the producer contract (`_validate_capture`), the envelope schema (`validate_runtime_identity_envelope`), the strengthened artifact validator |
| `benchmarks/adapters.py` | the envelope is read from the response only when it is an envelope; a broken envelope fails the target closed |
| `benchmarks/validate_iteration18_evidence.py` | fresh-state validation script with the `P0.1.response_envelope_binding` check + offline producer rehearsal |
| `benchmarks/evidence/iteration18_validation_evidence.json` | published validation artifact |
| `benchmarks/evidence/iteration18_producer_rehearsal/` | the artifacts the producer rehearsal wrote (re-verifiable bytes) |
| `benchmarks/evidence/iteration18_change_impact_matrix.md` | this matrix |
| `tests/test_iteration18_evidence_integrity.py` | adversarial test suite |
| `tests/test_iteration17_evidence_integrity.py` | two helpers keep the artifacts internally consistent (no assertion weakened) |
| `.github/workflows/ci.yml` | run the Iteration 18 suite and the Iteration 18 validator |

---

## 6. Results of this iteration

The results are filled in after the code, the tests and the evidence are
committed; the numbers of the local run and the numbers of the CI run are
reported separately.
