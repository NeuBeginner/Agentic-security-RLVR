# Iteration 15 Change Impact Matrix (Issue #11, PR #12 follow-up)

Branch: `minimax/iteration-14-evidence-integrity`
Base of this iteration: `8914cb5` (Iteration 14 validation-evidence commit)
PR base: `integration/minimax-antigravity-reconciled`

Scope: close the two validator weaknesses the Iteration 14 review named.

1. A non-empty `invocation_id` plus an App ID was accepted as proof that a billing line item
   belongs to a target, and an App/resource/interval aggregate bucket could be allocated to an
   individual target.
2. A `NOT_AVAILABLE` provenance fact was accepted with a reason string alone; a missing,
   malformed or tampered evidence reference was not detected, and App IDs were never
   cross-checked between the invocation evidence and the billing export.

The matrix was written **before** the code changes and updated afterwards to the names that
actually exist in the final implementation.

Implementation anchor: `benchmarks/evidence_integrity.py` holds the fact primitives
(`observed`, `not_available`), the immutable `EvidenceRef`, the billing join primitives and every
validator. `benchmarks/protocol.py` keeps the historical public function names and delegates to
that module.

---

## 1. Billing attribution must prove an exact, unique join

| Requirement | Producer | Consumer | Serializer / report path | Invariant | Cases | Named tests |
|---|---|---|---|---|---|---|
| A join must reference a provider-issued correlation key that the raw export really carries | `benchmarks/evidence_integrity.py::BillingLineItem.provider_keys` populated by `load_raw_billing_line_items` from the documented provider join fields (`invocation_id`, `function_call_id`, `task_id`) | `benchmarks/evidence_integrity.py::resolve_billing_join` | `benchmarks/evidence/modal_billing_join_table.json` → `target_level[].invocation_join.provider_key` | a join value that occurs on no raw line item is never attributed | missing key / unsupported key / fabricated value / valid unique value | `test_iteration15_billing_rejects_missing_join_key`, `test_iteration15_billing_rejects_fabricated_invocation_id`, `test_iteration15_billing_accepts_unique_provider_backed_join` |
| The join must resolve to exactly one raw line item | `resolve_billing_join` counts the matching raw line items | `resolve_billing_join`, `validate_billing_attribution` | `target_level[].invocation_join.line_item_key` | zero matches and more than one match are both rejected | one match / many-to-one match / duplicated raw row | `test_iteration15_billing_rejects_ambiguous_provider_join`, `test_iteration15_billing_rejects_duplicate_billing_row` |
| The joined line item must belong to the App ID the join claims | `BillingLineItem.object_id` from the raw export | `resolve_billing_join` | `target_level[].invocation_join.app_id` | a join that names a different App ID than the matched billing record is rejected | correct App ID / wrong App ID | `test_iteration15_billing_rejects_wrong_app_id` |
| One raw line item may be claimed by at most one target | `build_billing_attribution` keeps a claim ledger per run | `build_billing_attribution`, `validate_billing_attribution` | `target_level[].cost_status` / `.cost_reason_code` | two targets may never receive the same billing record, and an aggregate bucket is never handed to one target | single claim / second claim rejected | `test_iteration15_billing_rejects_two_targets_sharing_one_bucket` |
| An App/resource/interval aggregate bucket is never allocated to an individual target | the bucket lookup of Iteration 14 is removed; only a resolved single line item carries a cost | `build_billing_attribution`, `validate_billing_attribution` | `app_session_level[]` (aggregates) and `target_level[]` (single records only) | a target cost always equals the cost of exactly one raw line item | aggregate allocation rejected / exact single-record allocation accepted | `test_iteration15_billing_rejects_aggregate_bucket_allocation`, `test_iteration15_billing_accepts_unique_provider_backed_join` |
| The attributed cost equals the joined billing record exactly | `decimal.Decimal` arithmetic in `build_billing_attribution` and `validate_billing_attribution` | `validate_billing_attribution` | `target_level[].cost_usd_exact` | no estimated, prorated or duplicated amount is ever published | exact cost / mismatching cost | `test_iteration15_billing_rejects_cost_that_does_not_match_the_joined_record` |
| Without an exact correlation the target cost stays `null` with a machine-readable reason | `build_billing_attribution` writes `cost_status` + `cost_reason_code` + `cost_reason` | `validate_billing_attribution`, `benchmarks/validate_iteration15_evidence.py` | `target_level[].cost_usd == null` | a null cost is only published together with a reason code | missing reason code rejected / documented reason accepted | `test_iteration15_billing_requires_reason_code_for_unattributed_target`, `test_saved_join_table_validates_against_the_raw_export` |
| Every raw line item is still accounted for exactly once at App/session level | `build_billing_attribution` groups by (app id, resource, interval) and assigns each raw row one index-qualified key | `validate_billing_attribution` | `app_session_level[].line_item_keys` | the App/session aggregate reconciles exactly with the raw export | counted once / double counted / dropped | `test_billing_line_items_are_counted_exactly_once`, `test_billing_detects_double_counted_line_item`, `test_billing_detects_dropped_line_item` |
| The published join table is reproducible from the immutable raw export | `benchmarks/regenerate_billing_join_table.py` (schema `3.0.0`) | `benchmarks/evidence_integrity.py::validate_billing_attribution` | `benchmarks/evidence/modal_billing_join_table.json` | the `--check` mode re-validates the committed table without rewriting it | regenerated table / `--check` mode | `test_iteration15_saved_join_table_is_schema_3_and_validates`, `test_saved_join_table_validates_against_the_raw_export`, `test_saved_join_table_does_not_repeat_aggregate_charges` |
| The documented provider correlation fields are exactly the allowed ones | `benchmarks/evidence_integrity.py::PROVIDER_JOIN_FIELDS` | `resolve_billing_join`, `validate_billing_attribution` | `attribution_policy.provider_join_fields` | same | `benchmarks/evidence/modal_billing_join_table.json` | documented field list | `test_iteration15_provider_join_fields_are_documented` |
| A cost without any join at all is rejected | `build_billing_attribution` (no join ⇒ `cost_usd = null`) | `validate_billing_attribution` | `target_level[].cost_usd` | same | target artifact | cost without a join rejected | `test_iteration15_billing_rejects_cost_without_any_join` |

## 2. Modal provenance evidence must be independently verifiable

| Requirement | Producer | Consumer | Serializer / report path | Invariant | Cases | Named tests |
|---|---|---|---|---|---|---|
| Every `NOT_AVAILABLE` fact carries an evidence reference and a SHA-256 digest | `benchmarks/adapters.py` persists the received runtime payload per target (`<target>_modal_provenance_evidence.json`) and attaches the reference to every `NOT_AVAILABLE` fact; `benchmarks/evidence_integrity.py::not_available` | `benchmarks/evidence_integrity.py::validate_modal_invocation_provenance` | `modal_invocation_provenance.stages.*.{app_id,function_call_id,container_id}.evidence_ref` | a reason string alone is never sufficient | absent reference / absent digest / valid reference | `test_iteration15_provenance_rejects_not_available_without_evidence_ref`, `test_iteration15_provenance_rejects_not_available_without_digest`, `test_iteration15_provenance_accepts_not_available_with_verified_evidence` |
| The digest is validated against the referenced bytes | `benchmarks/evidence_integrity.py::validate_evidence_ref_bytes` re-reads the referenced file and recomputes SHA-256 | `validate_modal_invocation_provenance`, `validate_evidence_ref_bytes` | same | a digest that does not match the bytes on disk is rejected | matching digest / tampered bytes / missing artifact / malformed digest | `test_iteration15_provenance_rejects_tampered_evidence_bytes`, `test_iteration15_provenance_rejects_malformed_digest`, `test_iteration15_provenance_rejects_missing_evidence_artifact` |
| The evidence reference must stay inside the evidence root | `resolve_evidence_path` rejects absolute paths and path traversal | `validate_evidence_ref_bytes` | same | a reference can never point outside the repository | absolute path / traversal | `test_iteration15_provenance_rejects_evidence_path_outside_the_evidence_root` |
| App IDs are cross-checked between the invocation evidence and the billing export | `benchmarks/adapters.py` records the worker-reported App ID; the raw export supplies the set of billed App IDs | `benchmarks/evidence_integrity.py::validate_modal_app_id_consistency` | `benchmarks/evidence/iteration15_validation_evidence.json` → `per_target[].P0.1.modal_app_id_consistency` | an App ID that is observed but absent from the billing export is rejected | matching App ID / mismatching App ID | `test_iteration15_provenance_rejects_app_id_mismatch`, `test_iteration15_provenance_accepts_matching_app_id` |
| An unavailable App ID is represented explicitly instead of being skipped | `validate_modal_app_id_consistency` returns one comparison record per scope with status `MATCHED`, `MISMATCHED` or `NOT_AVAILABLE_NOT_COMPARED` | `benchmarks/validate_iteration15_evidence.py` | same | no comparison is silently skipped | unavailable App ID recorded as `NOT_AVAILABLE_NOT_COMPARED` | `test_iteration15_provenance_records_unavailable_app_id_explicitly` |
| The App ID of every stage is validated for shape and provenance | `modal_app.py::capture_modal_runtime_identity` (provider-issued values only) | `validate_modal_invocation_provenance` | `modal_invocation_provenance.stages.*` | no hardcoded or synthetic identity survives | observed / malformed / synthetic container id | `test_iteration15_provenance_accepts_fully_observed_facts`, `test_modal_provenance_accepts_fully_observed_facts`, `test_modal_provenance_rejects_malformed_app_id`, `test_modal_provenance_rejects_synthetic_container_id` |
| The evidence reference itself is well formed and points at existing bytes | `benchmarks/evidence_integrity.py::validate_evidence_ref_bytes`, `resolve_evidence_path` | `validate_modal_invocation_provenance` | `evidence_ref.{path,sha256,byte_length}` | same | valid digest / tampered bytes / missing artifact / malformed digest / path traversal | `test_iteration15_evidence_ref_bytes_helper_validates_the_digest`, `test_iteration15_resolve_evidence_path_rejects_traversal`, `test_iteration15_provenance_rejects_tampered_evidence_bytes`, `test_iteration15_provenance_rejects_missing_evidence_artifact`, `test_iteration15_provenance_rejects_malformed_digest` |
| The evidence reference is attached to every `NOT_AVAILABLE` fact without mutating the source payload | `benchmarks/evidence_integrity.py::attach_evidence_ref_to_facts` | `validate_modal_invocation_provenance` | `modal_invocation_provenance.stages.*.evidence_ref` | same | recursive attachment | `test_iteration15_attach_evidence_ref_to_facts_is_recursive` |
| The cross-check itself reports a mismatch | `benchmarks/evidence_integrity.py::cross_check_app_ids` | `benchmarks/validate_iteration15_evidence.py` | `per_target[].P0.1.modal_app_id_consistency.comparisons` | same | mismatch reported | `test_iteration15_provenance_cross_check_reports_mismatch` |

## 3. Validation artifact and CI

| Requirement | Producer | Consumer | Serializer / report path | Invariant | Cases | Named tests |
|---|---|---|---|---|---|---|
| A fresh validation artifact is bound to the exact final code SHA | `benchmarks/validate_iteration15_evidence.py` | CI + PR comment | `benchmarks/evidence/iteration15_validation_evidence.json` | the bound SHA is a real commit of this branch's history | bound SHA / foreign SHA | `test_iteration15_validation_evidence_is_bound_to_the_code_sha`, `test_iteration15_validation_evidence_check_mode_detects_a_foreign_code_sha` |
| Observed facts are separated from inferred or unavailable data | `validate_iteration15_evidence.py` (per-target provider fact inventory) | the PR comment | `per_target[].provider_facts` | the report never claims a provider fact that was not observed | observed / not available | `test_iteration15_validation_evidence_separates_observed_from_unavailable` |
| The report states the honest verdict for the saved run | `validate_iteration15_evidence.py` | the PR comment | `summary.overall_status`, `interpretation` | no Modal runtime validation is claimed | saved run fails the new checks / billing reconciliation passes | `test_iteration15_validation_evidence_reports_the_saved_run_honestly` |
| The new suite runs in CI | `.github/workflows/ci.yml` | CI | workflow steps | the Iteration 15 suite is executed on every push and pull request | CI configuration | `test_iteration15_ci_workflow_runs_the_new_suite` |

## Out of scope (unchanged by this iteration)

* The remote EVM provenance contract of Iteration 14 P0.3 (`reason` only for a `NOT_AVAILABLE`
  fact) — the review scoped requirement 2 to the Modal provenance evidence.
* The replay envelope contract of Iteration 14 P0.2.
* `main`, PR #8 and `integration/minimax-antigravity-reconciled` are not modified.
* No H100 and no paid GPU benchmark is executed; no Modal runtime validation is claimed.
