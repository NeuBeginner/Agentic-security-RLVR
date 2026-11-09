# Iteration 17 — Change Impact Matrix

**Iteration:** 17 (PR #12 follow-up)
**Scope:** P0.1 — the stage-evidence state machine: the flags of a stage evidence artifact and the kind of absence it records must agree, and a combination that cannot happen must be rejected.
**Trigger:** independent review comment `issuecomment-6750608950` (2026-11-09) and the review clarification `issuecomment-6750614569`.

---

## 1. The defect this iteration removes

Iteration 16 gave every stage its own evidence artifact and distinguished the
kinds of absence. The *combination* of the flags and the kind was still checked
one by one, so combinations that cannot happen could still pass:

1. **The provider-omission bypass.** The `PROVIDER_FIELD_OMITTED` branch checked
   that a response and a runtime envelope existed and that the field was not
   `OBSERVED`. It did **not** require the field to be listed in
   `requested_fields`. An artifact could therefore claim that the provider
   omitted, for example, `container_id` even though the client never requested
   `container_id` — a statement about the provider that nobody can prove.
2. **No complete stage-state invariants.** `STAGE_EXECUTED_NO_RUNTIME_ENVELOPE`
   required `executed=True` and `runtime_envelope_received=False` but not
   `response_received=True`, so a contradictory "the stage answered and, at the
   same time, received no response" state passed. The other kinds had the same
   gap.
3. **No completeness of the absence records.** An artifact could leave an
   identity field unaccounted for, or account for the same field twice.

The defect is structural: there was no state machine, only per-field checks.

---

## 2. Design

### 2.1 One state table

The four flags of a stage describe exactly one state. Every other combination
is impossible and is rejected before a single absence record is looked at.

| state | `attempted` | `executed` | `response_received` | `runtime_envelope_received` | meaning |
| --- | --- | --- | --- | --- | --- |
| `NOT_ATTEMPTED` | false | false | false | false | the stage was never invoked |
| `ATTEMPT_FAILED_NO_RESPONSE` | true | false | false | false | the stage was invoked and no response came back |
| `RESPONSE_RECEIVED_NOT_EXECUTED` | true | false | true | false | the stage answered but did not complete |
| `EXECUTED_NO_RUNTIME_ENVELOPE` | true | true | true | false | the stage completed, its answer carried no envelope |
| `EXECUTED_WITH_RUNTIME_ENVELOPE` | true | true | true | true | the stage completed and its answer carried an envelope |

16 combinations of four flags, **5 of them are states**, 11 are impossible:

```
(0,0,0,0)  (1,0,0,0)  (1,0,1,0)  (1,1,1,0)  (1,1,1,1)
```

Everything else is rejected — among them "not attempted + executed/response/
envelope", "executed without a response", "a response without the stage having
been attempted", and "an envelope without a response".

`RESPONSE_RECEIVED_NOT_EXECUTED` exists because the producer can observe it: the
trajectory-persistence worker may answer with something that is not the stored
path (`persistence_status == "unknown_response"`). The client then holds a
response and the stage did not complete — a truthful state, not a failed
attempt. A *failed attempt* is `ATTEMPT_FAILED_NO_RESPONSE`, where no response
came back at all, and the rules below keep the two apart.

### 2.2 The rules of every kind of absence

Each kind names the states it may describe and what `requested_fields` must say
about the field in question.

| kind | states it may describe | `requested_fields` |
| --- | --- | --- |
| `STAGE_NOT_ATTEMPTED` | `NOT_ATTEMPTED` | irrelevant |
| `STAGE_ATTEMPT_FAILED_NO_RESPONSE` | `ATTEMPT_FAILED_NO_RESPONSE` | irrelevant |
| `CLIENT_NEVER_CAPTURED_FIELD` | every state in which the stage answered | the field must **not** be listed |
| `STAGE_EXECUTED_NO_RUNTIME_ENVELOPE` | `RESPONSE_RECEIVED_NOT_EXECUTED`, `EXECUTED_NO_RUNTIME_ENVELOPE` | the field must be listed |
| `PROVIDER_FIELD_OMITTED` | `EXECUTED_WITH_RUNTIME_ENVELOPE` | the field must be listed |

A `PROVIDER_FIELD_OMITTED` therefore needs, at the same time: a state in which
the stage answered **and** its answer carried a runtime-identity envelope, and
a field the client actually asked for. The bypass of the review is closed by
the second half of that sentence.

`STAGE_EXECUTED_NO_RUNTIME_ENVELOPE` describes the **response** ("the answer
carried no runtime-identity envelope"); whether the stage completed is stated by
the state table, not by the kind.

### 2.3 One classifier for the producer and the validator

`classify_absence_kind()` is the single classifier of the evidence chain. The
producer calls it to write the absence records (`build_stage_evidence_artifact`,
`build_stage_identity_facts`), and the validator calls it to check them. A
record can therefore never claim a kind that the state of its own artifact does
not allow: the two sides cannot drift apart.

### 2.4 Complete and unique absence records

For every identity field the validator derives the kind the state allows and
compares it with the artifact:

* a field the provider reported must have **no** absence record;
* a field the state leaves unavailable must have **exactly one** record, and
  that record must carry exactly the derived kind;
* a field with **two** records is rejected.

### 2.5 The evidence wording: canonical JSON, not transport bytes

The stage artifact hashes a **canonical JSON serialization of the returned
Python payload** — not the raw transport bytes the provider sent. The payload
is a Python object that was decoded by the SDK; the digest is computed over
`canonical_json_bytes(payload)` and can be recomputed from the bytes stored
inside the artifact. Nowhere in this iteration is a canonicalized SDK object
described as the bytes the provider put on the wire.

---

## 3. Change Impact Matrix

| # | Requirement | Producer (evidence is created here) | Validator (evidence is enforced here) | Evidence location | Accepted when | Positive test | Negative (adversarial) tests |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | The four flags of a stage describe exactly one state | `benchmarks/evidence_integrity.py::build_stage_evidence_artifact` writes the flags of the capture | `validate_stage_evidence_artifact` → `_stage_state_of` → `STAGE_STATE_TABLE` | `<target>_stage_evidence_<stage>.json` → the four flags | the combination is one of the five states | `test_iteration17_every_state_of_the_table_is_accepted` | `test_iteration17_impossible_flag_combinations_are_rejected` (11 combinations), `test_iteration17_state_table_rejects_every_impossible_combination` |
| 2 | A provider omission needs a field the client requested | `classify_absence_kind` returns `PROVIDER_FIELD_OMITTED` only for a requested field | `_check_absence_record_against_flags` (`ABSENCE_REQUESTED_PRESENT`) | `absence_records[].kind` + `requested_fields` | the field is listed in `requested_fields` | `test_iteration17_provider_omission_may_be_claimed_for_a_requested_field` | `test_iteration17_provider_omission_for_an_unrequested_field_is_rejected` (the exact bypass of the review), `test_iteration17_provider_omission_needs_the_field_in_requested_fields` |
| 3 | A provider omission needs a response and an envelope | the producer only reaches that kind in `EXECUTED_WITH_RUNTIME_ENVELOPE` | `ABSENCE_KIND_RULES` (the kind is bound to one state) + the envelope check | same | the state carries an envelope and a response | `test_iteration17_the_honest_four_stage_case_is_accepted` | `test_iteration17_provider_omission_requires_a_response_and_an_envelope`, `test_iteration17_an_artifact_that_claims_an_envelope_must_hold_one`, `test_iteration17_provider_omission_must_be_genuinely_absent` |
| 4 | "Response without a runtime envelope" needs a response | the producer classifies the kind only when a response came back | `ABSENCE_KIND_RULES` (`STAGE_EXECUTED_NO_RUNTIME_ENVELOPE` → the states with a response) | same | `response_received` is true in that state | `test_iteration17_the_honest_four_stage_case_is_accepted` | `test_iteration17_executed_without_envelope_requires_a_response` |
| 5 | A failed attempt cannot coexist with a response | `classify_absence_kind` returns the failed-attempt kind only without a response | `ABSENCE_KIND_RULES` (the kind is bound to `ATTEMPT_FAILED_NO_RESPONSE`) | same | the state has no response | `test_iteration17_every_state_of_the_table_is_accepted` | `test_iteration17_failed_attempt_may_not_claim_a_response` |
| 6 | A stage that was never invoked cannot have executed | the producer writes `attempted=False` only for a stage it never invoked | `STAGE_STATE_TABLE` (no state has `attempted=False` with `executed=True`) | same | the flags are one of the five states | `test_iteration17_state_table_covers_every_state_of_a_stage` | `test_iteration17_not_attempted_may_not_execute`, `test_iteration17_impossible_flag_combinations_are_rejected` |
| 7 | "Never captured" needs a field the client did not request | `classify_absence_kind` returns `CLIENT_NEVER_CAPTURED_FIELD` only for an unrequested field | `ABSENCE_REQUESTED_ABSENT` | same | the field is **not** listed in `requested_fields` | `test_iteration17_the_honest_four_stage_case_is_accepted` | `test_iteration17_client_never_captured_requires_an_unrequested_field` |
| 8 | A kind may only be claimed in the states that allow it | the producer writes the derived kind | `ABSENCE_KIND_RULES` + `_check_absence_record_against_flags` | same | the state is listed for the kind | `test_iteration17_kind_rules_match_what_can_really_happen` | `test_iteration17_a_kind_may_only_be_claimed_in_the_states_that_allow_it` (25 state/kind pairs) |
| 9 | The absence records are complete and unique | `build_stage_evidence_artifact` writes one record per unavailable field | `validate_stage_evidence_artifact` (completeness and uniqueness) | `absence_records[]` | every unavailable field has exactly one record | `test_iteration17_the_producer_writes_artifacts_the_validator_accepts` | `test_iteration17_a_missing_absence_record_is_rejected`, `test_iteration17_a_duplicate_absence_record_is_rejected`, `test_iteration17_an_absence_record_for_an_observed_field_is_rejected`, `test_iteration17_the_recorded_kind_must_match_the_state` |
| 10 | The producer and the validator share one classifier | `classify_stage_absence` → `classify_absence_kind` | `validate_stage_evidence_artifact` → `classify_absence_kind` | — | the record kind equals the derived kind | `test_iteration17_producer_and_validator_share_one_classifier` | `test_iteration17_the_recorded_kind_must_match_the_state` |
| 11 | Only a provider omission may blame the provider | the producer's reason texts are kind-specific | `PROVIDER_OMISSION_PHRASE_RE` check (unchanged) | `absence_records[].reason` | the wording matches the kind | `test_iteration17_only_a_provider_omission_may_blame_the_provider` | `test_iteration17_only_a_provider_omission_may_blame_the_provider` |
| 12 | The evidence wording stays honest: canonical JSON, not transport bytes | `canonical_json_bytes` computes every payload digest | `validate_stage_evidence_artifact` recomputes it | `provider_response_metadata.response_sha256` | the digest is the digest of the canonical serialization | `test_iteration17_the_artifact_hashes_the_canonical_json_of_the_payload` | `test_iteration17_the_documentation_keeps_the_canonical_distinction` |
| 13 | A fresh validation artifact is published and bound to the code SHA | `benchmarks/validate_iteration17_evidence.py` | the script itself | `benchmarks/evidence/iteration17_validation_evidence.json` | the report names the code SHA it was produced from | `test_iteration17_validation_evidence_is_bound_to_the_code_sha` | `test_iteration17_validation_evidence_check_mode_detects_a_foreign_code_sha` |
| 14 | CI runs the new suite and the new validator | `.github/workflows/ci.yml` | — | `.github/workflows/ci.yml` | the workflow references both | `test_iteration17_ci_workflow_runs_the_new_suite` | — |
| 15 | The producer path is rehearsed offline against faithful worker responses | `benchmarks/validate_iteration17_evidence.py` runs the real producer | the Iteration 17 validators | `benchmarks/evidence/iteration17_producer_rehearsal/` | the rehearsal passes and every stage shows its own state | `test_iteration17_the_producer_writes_artifacts_the_validator_accepts` | `test_iteration17_every_state_of_the_table_is_accepted` |

---

## 3.1 The exact API of this iteration

| symbol | module | role |
| --- | --- | --- |
| `STAGE_FLAG_NAMES` | `benchmarks/evidence_integrity.py` | the four flags that describe a stage |
| `STAGE_STATE_TABLE` | `benchmarks/evidence_integrity.py` | the state table: flags → state |
| `STAGE_STATE_*` | `benchmarks/evidence_integrity.py` | the names of the five states |
| `ABSENCE_KIND_RULES` | `benchmarks/evidence_integrity.py` | for every kind: the states it may describe and the rule for `requested_fields` |
| `ABSENCE_REQUESTED_PRESENT/ABSENT/IRRELEVANT` | `benchmarks/evidence_integrity.py` | what `requested_fields` must say |
| `classify_absence_kind` | `benchmarks/evidence_integrity.py` | the single classifier of the chain |
| `_stage_state_of` | `benchmarks/evidence_integrity.py` | the state an artifact's flags describe |
| `validate_stage_evidence_artifact` | `benchmarks/evidence_integrity.py` | internal consistency: state, kinds, completeness, uniqueness |
| `validate_iteration17_evidence` | `benchmarks/validate_iteration17_evidence.py` | fresh-state validation + offline producer rehearsal |

---

## 4. Honest boundaries of this iteration

* **No live Modal run, no H100, no paid GPU.** The producer path is exercised
  offline against faithful worker responses; the historical saved run predates
  this fix and is reported as `FAILED` by the validator — that is the honest
  outcome, exactly as in Iterations 15 and 16.
* **The saved 16-target run still fails the new check.** It was produced before
  Iteration 16 gave every stage its own artifact; the report says `FAILED
  16/16` for the stage binding and for the state machine. A green CI workflow
  is **not** a successful 16-target benchmark validation.
* **The CI counts and the local counts are reported separately.** The CI
  full-suite step of run `42680441114` reported *514 passed, 11 skipped*, not
  the *524 passed, 1 skipped* that the Iteration 16 comment claimed; the
  Iteration 17 report states the numbers of the run it actually describes.
* **The deployed workers are not changed in this iteration.** The inference and
  the trajectory-persistence stages still return no runtime-identity envelope
  from the workers of today.
* **The billing part of Iteration 15 is not touched.**

---

## 5. Files touched

| file | change |
| --- | --- |
| `benchmarks/evidence_integrity.py` | the state table, the rules of the kinds, the shared classifier, the strengthened artifact validator |
| `benchmarks/adapters.py` | producer comments: canonical JSON serialization, not raw transport bytes |
| `benchmarks/validate_iteration17_evidence.py` | fresh-state validation script with the `P0.1.stage_state_machine` check + offline producer rehearsal |
| `benchmarks/evidence/iteration17_validation_evidence.json` | published validation artifact |
| `benchmarks/evidence/iteration17_producer_rehearsal/` | the artifacts the producer rehearsal wrote (re-verifiable bytes) |
| `benchmarks/evidence/iteration17_change_impact_matrix.md` | this matrix |
| `benchmarks/evidence/iteration16_change_impact_matrix.md` | the wording of the payload digest corrected (canonical JSON, not verbatim transport bytes) |
| `tests/test_iteration17_evidence_integrity.py` | adversarial test suite |
| `.github/workflows/ci.yml` | run the Iteration 17 suite and the Iteration 17 validator |

---

## 6. Results of this iteration

The exact numbers are filled in by the PR comment of this iteration; the
committed validation artifact carries the machine-readable version of them.
