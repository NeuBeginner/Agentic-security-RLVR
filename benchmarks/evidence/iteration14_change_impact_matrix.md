# Iteration 14 Change Impact Matrix (Issue #11)

Branch: `minimax/iteration-14-evidence-integrity`
Base commit (Issue-mandated): `47e49b9389753d6ce3a7075d0d1cef9cc2c5d5d7`
PR base: `integration/minimax-antigravity-reconciled`

Scope: repair the benchmark evidence chain so that provenance and statuses are backed by
actually observed data, never by constants, fallbacks or declarative fields.

Implementation anchor: `benchmarks/evidence_integrity.py` holds the four fact primitives
(`observed`, `not_available`), the immutable `EvidenceRef`, and every Iteration 14
validator. `benchmarks/protocol.py` keeps the historical public function names and
delegates to that module, so existing callers and tests keep working.

The matrix was written **before** the code changes and is updated here to the names that
actually exist in the final implementation.

---

## P0.1 Modal provenance and billing attribution

| Requirement | Producer | Consumer | Schema | Artifact | Positive test | Negative test |
|---|---|---|---|---|---|---|
| No hardcoded Modal App ID | `benchmarks/adapters.py` (literal `ap-EDUitOwWeMrIdYbTh4kB63` deleted), `modal_app.py::capture_modal_runtime_identity` (worker reports its own runtime identity) | `benchmarks/evidence_integrity.py::validate_modal_invocation_provenance` | `modal_invocation_provenance.stages.*.app_id` | per-target JSON artifact, `tool_metadata.modal_invocation_provenance` | `test_modal_provenance_accepts_fully_observed_facts` | `test_modal_provenance_rejects_malformed_app_id`, `test_producer_sources_contain_no_hardcoded_app_id_or_synthetic_uri` |
| No synthetic `modal-app://` log URIs | `benchmarks/adapters.py` (URI construction deleted), `benchmarks/regenerate_billing_join_table.py` (regenerated join table carries no URI) | `validate_modal_invocation_provenance`, `benchmarks/evidence_integrity.py::has_synthetic_modal_uri` | `stages.*.durable_log_ref` / `provider_log_uri` / `log_uri` | same + `benchmarks/evidence/modal_billing_join_table.json` | `test_saved_join_table_validates_against_the_raw_export` | `test_modal_provenance_rejects_synthetic_log_uri`, `test_has_synthetic_modal_uri_detects_fabricated_uris` |
| Capture provider-issued app / function-call / container IDs | `modal_app.py::capture_modal_runtime_identity` (`modal.running_app().app_id`, `modal.current_function_call_id()`, `MODAL_WORKER_ID`/`HOSTNAME`) | `validate_modal_invocation_provenance` | `stages.*.{app_id,function_call_id,container_id}` | same | `test_modal_provenance_accepts_fully_observed_facts` | `test_modal_provenance_rejects_synthetic_container_id`, `test_modal_provenance_rejects_unknown_app_id` |
| Missing provider field → `NOT_AVAILABLE` + reason + immutable evidence ref (SHA-256) | `benchmarks/evidence_integrity.py::not_available` + `build_evidence_ref` | `validate_modal_invocation_provenance` | `stages.*.reason`, `stages.*.evidence_ref.sha256` | same + `benchmarks/evidence/modal_billing_report_raw.json` | `test_not_available_fact_carries_reason_and_evidence_digest` | `test_modal_provenance_rejects_not_available_without_reason`, `test_evidence_ref_is_none_for_missing_artifact` |
| Billing: app/session level separated from target level | `benchmarks/evidence_integrity.py::build_billing_attribution`, driven by `benchmarks/regenerate_billing_join_table.py` | `benchmarks/evidence_integrity.py::validate_billing_attribution` | `app_session_level[]`, `target_level[]` | `benchmarks/evidence/modal_billing_join_table.json` (schema 2.0.0) | `test_billing_line_items_are_counted_exactly_once` | `test_billing_detects_double_counted_line_item`, `test_billing_detects_dropped_line_item` |
| Target-level cost stays `null` without proven invocation-level join | `build_billing_attribution` (Modal billing has no invocation→line-item join ⇒ `null`) | `validate_billing_attribution` | `target_level[].cost_usd`, `.cost_status` | same | `test_target_cost_is_null_without_proven_join`, `test_saved_join_table_does_not_repeat_aggregate_charges` | `test_billing_rejects_target_cost_without_join_evidence` |
| Referenced app IDs exist in the raw export | raw export `benchmarks/evidence/modal_billing_report_raw.json` (25 line items, 9 app IDs) | `validate_billing_attribution` | `app_session_level[].app_id` | same | `test_saved_join_table_validates_against_the_raw_export` | `test_billing_rejects_unknown_app_id` |
| Aggregates reconcile exactly | `decimal.Decimal` arithmetic in `build_billing_attribution` / `validate_billing_attribution` | `validate_billing_attribution` | `app_session_level[].cost_usd_exact`, `total_cost_usd_exact` | same | `test_saved_join_table_validates_against_the_raw_export` | `test_billing_detects_aggregate_mismatch` |

## P0.2 Replay integrity envelope

| Requirement | Producer | Consumer | Schema | Artifact | Positive test | Negative test |
|---|---|---|---|---|---|---|
| No replay fallbacks (hashes / timestamps / container id) | `benchmarks/adapters.py` (every `or`-fallback deleted), `modal_app.py::verify_replay_remote` (returns real values only) | `benchmarks/evidence_integrity.py::validate_replay_evidence_envelope` | `replay_evidence.*` | per-target JSON artifact | `test_replay_envelope_accepts_complete_evidence` | `test_replay_envelope_rejects_missing_bytes`, `test_incomplete_replay_envelope_is_never_confirmed` |
| Replay stdout/stderr stored as separate artifacts with path, byte length, SHA-256 | `benchmarks/evidence_integrity.py::persist_replay_artifact` (exact bytes, `open(...,'wb')`) | `validate_replay_evidence_envelope` (recomputes the digest from the stored bytes) | `replay_evidence.stdout_artifact{path,byte_length,sha256}` | `<target>_replay_stdout.txt`, `<target>_replay_stderr.txt` | `test_replay_envelope_accepts_complete_evidence` | `test_replay_envelope_rejects_hash_mismatch_with_stored_file`, `test_replay_envelope_rejects_byte_length_mismatch` |
| Candidate/harness hashes compared to the exact replay input artifacts | `persist_replay_artifact` (writes candidate + harness bytes) | `validate_replay_evidence_envelope` | `replay_evidence.candidate_input_artifact`, `.harness_input_artifact` | `<target>_replay_candidate.sol`, `<target>_replay_harness.t.sol` | `test_replay_envelope_accepts_complete_evidence` | `test_replay_envelope_rejects_modified_candidate_or_harness`, `test_replay_envelope_rejects_candidate_that_is_not_the_executed_one` |
| Real fresh container identity required | `modal_app.py::capture_modal_runtime_identity` (`MODAL_WORKER_ID`/`HOSTNAME`) | `validate_replay_evidence_envelope` | `replay_evidence.container_id` | same | `test_replay_envelope_accepts_complete_evidence` | `test_replay_envelope_rejects_synthetic_container_id` |
| Replay-specific timestamps | `modal_app.py::verify_replay_remote` measures start/end inside the replay worker | `validate_replay_evidence_envelope` | `replay_evidence.utc_start_time` / `.utc_end_time` | same | `test_replay_envelope_accepts_complete_evidence` | `test_replay_envelope_rejects_initial_run_timestamps` |
| Exact argv and exit code | the worker returns the argv it really executed and the real return code | `validate_replay_evidence_envelope` | `replay_evidence.argv` / `.exit_code` | same | `test_replay_envelope_accepts_complete_evidence` | `test_replay_envelope_rejects_missing_argv`, `test_replay_envelope_rejects_wrong_exit_code` |
| Trusted harness verdict is a real breach | `modal_app.py::verify_replay_remote` (`HARNESS_VERDICT_BREACH` + `invariant_violated`) | `validate_replay_evidence_envelope` | `replay_evidence.harness_verdict` | same | `test_replay_envelope_accepts_complete_evidence` | `test_replay_envelope_requires_real_harness_breach_verdict` |
| Never `CONFIRMED` on an incomplete envelope | `benchmarks/adapters.py` (`rep_status` is derived from the client-side validation result) | `validate_replay_evidence_envelope` | `replay_status`, `tool_metadata.replay_envelope_valid` | same | `test_full_aegis_rlvr_invokes_modal_remote_functions` | `test_incomplete_replay_envelope_is_never_confirmed` |

## P0.3 Remote EVM provenance

| Requirement | Producer | Consumer | Schema | Artifact | Positive test | Negative test |
|---|---|---|---|---|---|---|
| Worker returns observed OS / forge / solc / argv / cwd / compiler settings | `sandbox/runner.py::observe_execution_environment` (+ `_observed_os_facts`, `_observed_forge_version`, `_observed_compiler_settings`), propagated by `modal_app.py::verify_exploit_remote` | `benchmarks/evidence_integrity.py::validate_remote_evm_toolchain_provenance` | `remote_evm_provenance.*` | per-target JSON artifact | `test_remote_evm_provenance_from_observed_facts`, `test_real_foundry_integration_observed_environment_carries_real_facts` | `test_remote_evm_provenance_rejects_hardcoded_source`, `test_remote_evm_provenance_rejects_legacy_hardcoded_forge_version`, `test_remote_evm_provenance_rejects_legacy_hardcoded_working_directory` |
| Immutable image digest, not a mutable tag | `sandbox/runner.py::_observed_image_digest` (`modal.config.image_id` inside the container) | `validate_remote_evm_toolchain_provenance` | `remote_evm_provenance.image_digest` | same | `test_remote_evm_provenance_from_observed_facts` | `test_remote_evm_provenance_rejects_mutable_image_tag_only`, `test_remote_evm_provenance_requires_immutable_image_digest` |
| Per target / per execution, never copied onto targets that did not run EVM | `benchmarks/adapters.py` attaches the provenance only when `evm_outcome != "NOT_RUN"` | `validate_remote_evm_toolchain_provenance` | `remote_evm_provenance` per target | same | `test_targets_without_evm_stage_have_no_evm_provenance` | `test_remote_evm_provenance_rejects_presence_on_not_run_target` |
| Unavailable fact → `NOT_AVAILABLE` + reason, never invented | `benchmarks/evidence_integrity.py::not_available` | `validate_remote_evm_toolchain_provenance` | `remote_evm_provenance.*.reason` | same | `test_remote_evm_provenance_accepts_not_available_with_reason` | `test_remote_evm_provenance_rejects_not_available_without_reason`, `test_remote_evm_provenance_rejects_empty_required_fact` |
| Provenance consistent with the actual execution record | the adapter records the same exit code the worker observed | `validate_remote_evm_toolchain_provenance` | cross-check against `process_exit_code` | same | `test_remote_evm_provenance_from_observed_facts` | `test_remote_evm_provenance_rejects_inconsistent_exit_code` |
| Run-level manifest does not broadcast a global fabricated environment | `benchmarks/benchmark_runner.py::_get_environment_manifest` (now `NOT_AVAILABLE` + reason) | artifact validators | `EnvironmentManifest.remote_evm_environment` | `reproducibility_manifest.json` | `test_run_manifest_has_no_hardcoded_remote_environment` | `test_run_manifest_has_no_hardcoded_remote_environment` |

## P0.4 Safe-control sentinel

| Requirement | Producer | Consumer | Schema | Artifact | Positive test | Negative test |
|---|---|---|---|---|---|---|
| Only the exact documented sentinel of the trusted harness is accepted | `benchmarks/evidence_integrity.py::HARNESS_SENTINELS` (mirrors the immutable harness sources), `benchmarks/protocol.py::validate_safe_control_sentinel_semantics` | the SAFE classification of a target | `harness_verdict`, revert reason | per-target JSON artifact, harness `.t.sol` sources | `test_safe_control_sentinel_accepts_exact_documented_sentinel`, `test_real_foundry_integration_safe_control_emits_the_exact_documented_sentinel` | `test_safe_control_sentinel_rejects_prefix_and_suffix`, `test_safe_control_sentinel_rejects_arbitrary_exploit_failed_prefix` |
| Target/harness context is checked | the sentinel registry is keyed by target name and matched against the harness suite path | `validate_safe_control_sentinel_semantics` | `target_name`, `harness_suite` | same | `test_sentinel_registry_matches_the_repository_harness_sources` | `test_safe_control_sentinel_requires_target_context`, `test_safe_control_sentinel_rejects_harness_context_mismatch`, `test_safe_control_sentinel_rejects_other_target_sentinel` |
| Generic revert / panic / compilation error / malformed output / infra failure rejected | same | same | reason classifier | same | `test_safe_control_sentinel_accepts_exact_documented_sentinel` | `test_safe_control_sentinel_rejects_generic_revert_panic_and_compile_error`, `test_safe_control_sentinel_rejects_infrastructure_failure`, `test_safe_control_sentinel_rejects_empty_reason`, `test_safe_control_sentinel_rejects_wrong_harness_verdict` |
| The four existing safe-control artifacts are verified | `benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/SAFE-01..04.json` + their `*_stdout.txt` | `tests/test_iteration14_evidence_integrity.py` | SAFE-01..04 verdicts | same | `test_all_saved_safe_control_artifacts_carry_their_exact_sentinel` | `test_saved_run_artifacts_do_not_pass_the_new_validators` |

## Cross-cutting

| Requirement | Producer | Consumer | Schema | Artifact | Positive test | Negative test |
|---|---|---|---|---|---|---|
| planned / attempted / executed / observed / reported stay distinguishable | `benchmarks/adapters.py`, `benchmarks/benchmark_runner.py` | `benchmarks/evaluator.py` | `orchestration_status`, `generation_outcome`, `evm_outcome`, `replay_status` | per-target JSON + summary | `test_full_aegis_rlvr_invokes_modal_remote_functions` | `test_incomplete_replay_envelope_is_never_confirmed` |
| Evidence artifacts written as exact bytes | `benchmarks/benchmark_runner.py` (`write_bytes`, no newline translation), `benchmarks/evidence_integrity.py::persist_replay_artifact` | the digest validators | `stdout_sha256`, `stderr_sha256`, `stdout_byte_length`, `stderr_byte_length` | `*_stdout.txt`, `*_stderr.txt`, `*_replay_*.txt` | `test_stored_stdout_digests_match_the_stored_bytes` | `test_replay_envelope_rejects_hash_mismatch_with_stored_file` |
| Validation evidence bound to the exact code SHA | `benchmarks/validate_iteration14_evidence.py` | CI + PR description | `code_sha`, `summary.overall_status`, `interpretation` | `benchmarks/evidence/iteration14_validation_evidence.json` | `test_validation_evidence_is_bound_to_the_code_sha` | `test_validation_evidence_reports_the_saved_run_honestly` |
| The billing join table is reproducible from the raw export | `benchmarks/regenerate_billing_join_table.py` | `benchmarks/evidence_integrity.py::validate_billing_attribution` | `schema_version: 2.0.0` | `benchmarks/evidence/modal_billing_join_table.json` | `test_saved_join_table_validates_against_the_raw_export` | `test_saved_join_table_does_not_repeat_aggregate_charges` |
