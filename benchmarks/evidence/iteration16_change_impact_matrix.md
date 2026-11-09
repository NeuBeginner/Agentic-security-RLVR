# Iteration 16 — Change Impact Matrix

**Iteration:** 16 (PR #12 follow-up)
**Scope:** P0.1 — producer-path provenance: the evidence bytes must cover **every** stage whose facts they are used for, and a missing fact must state *honestly* why it is missing.
**Trigger:** independent review comment `issuecomment-6742503301` (2026-11-09).

---

## 1. The defect this iteration removes

Iteration 15 made every `NOT_AVAILABLE` fact carry a digest-verifiable evidence
reference. The reference, however, pointed at **one shared file per target**
(`<target>_modal_provenance_evidence.json`) that contained only the EVM and the
replay runtime payload. The inference and the trajectory-persistence facts were
backed by that same file:

* an inference fact claimed "the runtime did not report this" while the file
  held the bytes of a *different* stage;
* a persistence fact was backed by the EVM stage's bytes;
* nothing in the artifact said **which stage** the bytes belonged to, so a
  digest-valid file could be reused for any fact.

The defect is structural: one artifact, four stages, no stage label.

---

## 2. Design

### 2.1 One evidence artifact per stage

The producer captures, **per stage**, what the provider actually returned and
writes it into its own file:

```
<target_id>_stage_evidence_inference.json
<target_id>_stage_evidence_evm_sandbox.json
<target_id>_stage_evidence_independent_replay.json
<target_id>_stage_evidence_trajectory_persistence.json
```

Each artifact carries:

| field | meaning |
| --- | --- |
| `schema_version` | `1.0.0` |
| `stage` | the stage the artifact belongs to — **the label that binds it** |
| `target_id`, `correlation_id` | the target and the run correlation id |
| `attempted` | the client invoked the stage |
| `executed` | the stage ran to completion |
| `response_received` | a response came back to this client |
| `runtime_envelope_received` | the response carried a runtime-identity envelope |
| `requested_fields` | the identity fields this client asked the stage to report |
| `provider_response` | the **exact returned payload**, verbatim |
| `provider_response_metadata` | `response_source`, the SHA-256 and the byte length of the returned payload, the keys of the enclosing response |
| `absence_records` | one typed record per absent identity field |

The digest of the returned payload is computed over a canonical encoding, so a
verifier can recompute it from the bytes stored inside the artifact.

### 2.2 Four (five) kinds of absence

The review requires at least four distinguishable kinds of "missing". The last
three must **not** be phrased as "the provider did not report":

| code | meaning |
| --- | --- |
| `PROVIDER_FIELD_OMITTED` | the provider returned a response and the field is absent from it (the field is either missing or carries the provider's own `NOT_AVAILABLE` marker) |
| `STAGE_NOT_ATTEMPTED` | the stage was never invoked |
| `STAGE_EXECUTED_NO_RUNTIME_ENVELOPE` | the stage ran and returned a response, but that response carried no runtime-identity envelope |
| `CLIENT_NEVER_CAPTURED_FIELD` | this client never requested the field from that stage |
| `STAGE_ATTEMPT_FAILED_NO_RESPONSE` | (extension) the stage was invoked but failed, so no response was received at all |

The kind is recorded **twice**: on the fact (`absence_kind`) and in the stage
artifact (`absence_records[].kind`). The validator rejects any disagreement.

### 2.3 The validator checks the correspondence, not only the digest

`validate_modal_invocation_provenance` now verifies, for every stage:

1. the stage's own `evidence_ref` resolves inside the evidence root and its
   digest matches the stored bytes (Iteration 15 guarantee, unchanged);
2. the referenced artifact **declares the same stage** — a wrong stage label is
   rejected;
3. every `NOT_AVAILABLE` fact of that stage references **that stage's** artifact
   — an EVM artifact can never back an inference fact;
4. the fact's `absence_kind` matches the artifact's absence record for the same
   field, and the record's kind is consistent with the artifact's own flags
   (e.g. `STAGE_NOT_ATTEMPTED` requires `attempted == false`);
5. only `PROVIDER_FIELD_OMITTED` may use provider-omission wording; the other
   kinds are rejected when their reason claims the provider did not report.

---

## 3. Change Impact Matrix

| # | Requirement | Producer (evidence is created here) | Validator (evidence is enforced here) | Evidence location | Accepted when | Positive test | Negative (adversarial) tests |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Every stage captures **its own** provider response, separately | `benchmarks/adapters.py` builds one `StageResponseCapture` per stage (inference, evm_sandbox, independent_replay, trajectory_persistence); `benchmarks/evidence_integrity.py::build_stage_evidence_artifact` / `write_stage_evidence_artifact` | `benchmarks/evidence_integrity.py::validate_stage_evidence_binding` | `benchmarks/artifacts/<run>/<target>_stage_evidence_<stage>.json` | one artifact per stage, each declaring its own `stage` | `test_iteration16_producer_writes_one_evidence_artifact_per_stage` | `test_iteration16_missing_stage_artifact_is_rejected` |
| 2 | The artifact records stage name, attempted/executed status, provider response metadata and the exact returned payload bytes | `StageResponseCapture` (attempted / executed / response_received / runtime_envelope_received / provider_response / response_source) | `validate_stage_evidence_artifact` | same | the metadata is complete and the payload digest is recomputable from the stored bytes | `test_iteration16_stage_artifact_records_the_returned_payload_bytes` | `test_iteration16_tampered_provider_response_is_rejected` |
| 3 | An inference fact may not cite EVM-only evidence | the inference facts carry the inference stage's `evidence_ref` | `validate_stage_evidence_binding` (fact path must equal the stage's own artifact path) | `modal_invocation_provenance.stages.inference.*.evidence_ref` | the fact references the artifact of its own stage | `test_iteration16_producer_binds_every_fact_to_its_own_stage` | `test_iteration16_inference_fact_cannot_reference_the_evm_artifact`, `test_iteration16_persistence_fact_cannot_reference_the_replay_artifact` |
| 4 | A wrong stage label is rejected | the artifact's `stage` field is written by the producer from the capture | `validate_stage_evidence_artifact(expected_stage=...)` | `…_stage_evidence_<stage>.json` → `stage` | the label equals the stage the facts live in | `test_iteration16_stage_label_must_match_the_stage` | `test_iteration16_mislabelled_stage_artifact_is_rejected` |
| 5 | The four kinds of absence are distinguishable and honest | `build_stage_identity_facts` classifies every missing field | `validate_stage_evidence_binding` (kind ↔ artifact record ↔ artifact flags) | fact `absence_kind`, artifact `absence_records[]` | the kind matches the situation that actually occurred | `test_iteration16_absence_kinds_are_distinguishable` | `test_iteration16_absence_kind_must_match_the_artifact_record`, `test_iteration16_not_attempted_may_not_claim_provider_omission` |
| 6 | The last three kinds must not say "the provider did not report" | the producer's reason texts are kind-specific | `PROVIDER_OMISSION_PHRASE_RE` check in `validate_stage_evidence_binding` | fact `reason`, artifact `absence_records[].reason` | the wording matches the kind | `test_iteration16_provider_omission_wording_is_allowed_only_for_omission` | `test_iteration16_not_attempted_reason_may_not_claim_the_provider_omitted_the_field` |
| 7 | Digest verification and evidence-root protection are preserved | `build_evidence_ref_from_bytes` (unchanged) | `validate_evidence_ref_bytes`, `resolve_evidence_path` (unchanged, still called first) | `evidence_ref.{path,sha256,byte_length}` | the digest matches the stored bytes and the path stays inside the root | `test_iteration16_stage_evidence_ref_is_digest_verified` | `test_iteration16_tampered_stage_evidence_bytes_are_rejected`, `test_iteration16_stage_evidence_path_cannot_escape_the_root` |
| 8 | The run-level App ID is bound to a concrete stage | the run-level fact references the EVM sandbox stage artifact | `validate_modal_invocation_provenance` (run-level binding check) | `modal_invocation_provenance.modal_app_id.evidence_ref` | it equals the EVM stage artifact path | `test_iteration16_run_level_app_id_is_bound_to_the_evm_stage` | `test_iteration16_run_level_app_id_cannot_reference_another_stage` |
| 9 | A fresh validation artifact is published and bound to the code SHA | `benchmarks/validate_iteration16_evidence.py` | the script itself | `benchmarks/evidence/iteration16_validation_evidence.json` | the report names the code SHA it was produced from | `test_iteration16_validation_evidence_is_bound_to_the_code_sha` | `test_iteration16_validation_evidence_check_mode_detects_a_foreign_code_sha` |
| 10 | CI runs the new suite and the new validator | `.github/workflows/ci.yml` | — | `.github/workflows/ci.yml` | the workflow references both | `test_iteration16_ci_workflow_runs_the_new_suite` | — |
| 11 | The producer path is rehearsed offline against faithful worker responses | `benchmarks/validate_iteration16_evidence.py::run_producer_rehearsal` runs the real producer and writes its artifacts into `benchmarks/evidence/iteration16_producer_rehearsal/` | the same Iteration 16 validators | `benchmarks/evidence/iteration16_producer_rehearsal/REENT-01_stage_evidence_*.json` | the rehearsal passes and every stage shows its own artifact | `test_iteration16_producer_writes_one_evidence_artifact_per_stage` | `test_iteration16_producer_records_honest_absence_for_every_stage` |
| 12 | The Iteration 15 evidence contract keeps its adversarial intent under the stronger one | `tests/test_iteration15_evidence_integrity.py::_evidence_artifact` now writes a real per-stage artifact | `validate_modal_invocation_provenance` (unchanged rules, stronger evidence contract) | `tests/test_iteration15_evidence_integrity.py` | the digest, the tampering and the path checks of Iteration 15 still reject the same cheats | `test_iteration15_provenance_accepts_not_available_with_verified_evidence` | `test_iteration15_provenance_rejects_tampered_evidence_bytes`, `test_iteration15_provenance_rejects_missing_evidence_artifact`, `test_iteration15_provenance_rejects_evidence_path_outside_the_evidence_root` |

---

## 3.1 The exact API of this iteration

| symbol | module | role |
| --- | --- | --- |
| `StageResponseCapture` | `benchmarks/evidence_integrity.py` | what one stage's provider response actually was |
| `build_stage_evidence_artifact` | `benchmarks/evidence_integrity.py` | builds the artifact of one stage |
| `write_stage_evidence_artifact` | `benchmarks/evidence_integrity.py` | writes it and describes its exact bytes |
| `build_stage_identity_facts` | `benchmarks/evidence_integrity.py` | the three identity facts of a stage, each with its kind of absence |
| `classify_stage_absence` | `benchmarks/evidence_integrity.py` | the classification itself |
| `canonical_json_bytes` | `benchmarks/evidence_integrity.py` | the encoding every evidence digest is computed over |
| `validate_stage_evidence_artifact` | `benchmarks/evidence_integrity.py` | internal consistency of one artifact |
| `validate_stage_evidence_binding` | `benchmarks/evidence_integrity.py` | the stage/evidence correspondence of one stage |
| `validate_stage_evidence_binding` | `benchmarks/protocol.py` | thin wrapper for the callers of the protocol layer |

---

## 4. Honest boundaries of this iteration

* **No live Modal run, no H100, no paid GPU.** The producer path is exercised
  offline against faithful worker responses (the same shape the real workers
  return, see `tests/test_real_benchmark_execution.py`); the historical saved
  run predates this fix and is reported as `FAILED` by the validator — that is
  the honest outcome, exactly as in Iteration 15.
* **The deployed workers are not changed in this iteration.** The inference and
  the trajectory-persistence stages still return no runtime-identity envelope
  from the workers of today, so the producer classifies those absences as
  `STAGE_EXECUTED_NO_RUNTIME_ENVELOPE` and `CLIENT_NEVER_CAPTURED_FIELD`
  instead of blaming the provider. Making the workers return an envelope is a
  follow-up that needs a Modal redeploy and is therefore out of scope here.
* **The billing part of Iteration 15 is not touched.**
* The saved artifacts of the historical run keep their old flat schema; they
  are rejected by the strengthened validator, and the validation report says so.

## 5. Files touched

| file | change |
| --- | --- |
| `benchmarks/evidence_integrity.py` | per-stage evidence API, absence classification, strengthened provenance validator |
| `benchmarks/adapters.py` | producer: one capture and one artifact per stage, per-stage evidence references |
| `benchmarks/protocol.py` | thin wrapper for the new stage-evidence validator |
| `benchmarks/validate_iteration16_evidence.py` | fresh-state validation script + offline producer rehearsal |
| `benchmarks/evidence/iteration16_validation_evidence.json` | published validation artifact |
| `benchmarks/evidence/iteration16_producer_rehearsal/` | the artifacts the producer rehearsal wrote (re-verifiable bytes) |
| `benchmarks/evidence/iteration16_change_impact_matrix.md` | this matrix |
| `tests/test_iteration16_evidence_integrity.py` | adversarial test suite |
| `tests/test_iteration15_evidence_integrity.py` | two tests updated to the strengthened evidence contract (same adversarial intent) |
| `.github/workflows/ci.yml` | run the Iteration 16 suite and the Iteration 16 validator |
