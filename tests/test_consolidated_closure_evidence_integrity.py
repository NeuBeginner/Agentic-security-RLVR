"""
tests/test_consolidated_closure_evidence_integrity.py
======================================================

The tests of the **consolidated closure** of PR #12.

Two defects are closed here, and both are tested at the **consumer boundary** -
at the real consumer, not at a helper:

* **P0 - the fail-closed evaluator leak.** A target whose execution did not
  complete (``FAILED`` / ``UNAVAILABLE``) was serialized in ``details[]`` as
  ``detected: false`` whenever its verdict was one of the negative verdicts.
  A run that did not complete produced **no finding at all**: its detection is
  ``None`` and its detection state is ``NOT_EVALUATED``.

* **P1 - the run-level observation-side gap.** The strict consumer side-checked
  the **stage** facts of an invocation, but the **run-level** application id
  ``modal_invocation_provenance.modal_app_id`` was only checked in its
  ``NOT_AVAILABLE`` shape. An observed run-level application id that names no
  side, a wrong side or a legacy flat value was accepted.

The compatibility path (the default, ``strict_sources=False``) is untouched and
keeps reading the side-less artifacts of Iterations 14-20.

**Boundaries.** No live Modal invocation, no provider query, no deployment, no
GPU. The ``OBSERVED`` branch of the producer is exercised in a **simulated**
container context (a patched ``modal.current_function_call_id``) and is called a
simulation wherever it is mentioned.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    NOT_AVAILABLE,
    OBSERVED,
    OBSERVATION_SIDE_CLIENT,
    OBSERVATION_SIDE_WORKER,
    PROVIDER_OBSERVATION_SOURCES,
    SOURCE_CLIENT_APP_ID,
    SOURCE_CLIENT_APP_PAGE_URL,
    SOURCE_CLIENT_CONTAINER_ID,
    SOURCE_WORKER_FUNCTION_CALL_ID,
    StageResponseCapture,
    build_modal_stage_provenance,
    build_stage_identity_facts,
    cross_check_app_ids,
    file_sha256,
    not_available,
    observed,
    sha256_bytes,
    validate_client_observed_facts,
    validate_modal_invocation_provenance,
    validate_provider_observation_source,
    validate_run_level_application_id,
    write_stage_evidence_artifact,
)
from benchmarks.evaluator import (  # noqa: E402
    DETECTION_STATE_NEGATIVE,
    DETECTION_STATE_NOT_EVALUATED,
    DETECTION_STATE_POSITIVE,
    evaluate_baseline_run,
    resolve_detection,
)
from benchmarks.protocol import (  # noqa: E402
    ExecutionStatus,
    GroundTruth,
    TargetExecutionArtifact,
)

STAGE = "evm_sandbox"
TARGET_ID = "CLOSURE-01"

#: The provider-issued identifiers the probes work with.
FUNCTION_CALL_ID = "fc-01M71H7789CATYCWNEG05916Y3"
APP_ID = "ap-gW7GDdh9OlSqjL2tRnB1oJ"
APP_PAGE_URL = f"https://modal.com/id/{APP_ID}"
CONTAINER_ID = "ta-01M71H78SAWD0JF71CFPA0QTRR"

#: The verdicts that force a negative finding of a **completed** execution.
NEGATIVE_VERDICTS = (
    "COMPILATION_ERROR",
    "RUNTIME_REVERT",
    "GENERATION_FORMAT_ERROR",
    "SAFE_RUN",
)

#: The statuses of an execution that did not complete.
INCOMPLETE_STATUSES = (ExecutionStatus.FAILED, ExecutionStatus.UNAVAILABLE)


# =============================================================================
# Helpers
# =============================================================================

def _producer_envelope() -> dict:
    """
    The envelope of the **real** producer in a simulated container context.

    ``modal.current_function_call_id`` is patched to return a fixed id: the
    ``OBSERVED`` branch of the producer is therefore exercised in a simulation,
    not in a live Modal container.
    """
    import modal
    import modal_app

    original = getattr(modal, "current_function_call_id", None)
    try:
        modal.current_function_call_id = lambda: FUNCTION_CALL_ID  # type: ignore[assignment]
        return modal_app.capture_modal_runtime_identity()
    finally:
        if original is None:
            try:
                del modal.current_function_call_id  # type: ignore[attr-defined]
            except AttributeError:
                pass
        else:
            modal.current_function_call_id = original  # type: ignore[attr-defined]


def _client_block() -> dict:
    """The client-observed block of a run."""
    return {
        "app_id": observed(
            APP_ID, source=SOURCE_CLIENT_APP_ID, observed_by=OBSERVATION_SIDE_CLIENT
        ),
        "app_page_url": observed(
            APP_PAGE_URL,
            source=SOURCE_CLIENT_APP_PAGE_URL,
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
        "container_id": not_available(
            "the provider was not asked in this probe",
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
    }


def _observed_fact(value, source, *, side=None, declare_side=True) -> dict:
    """A synthetic observed fact - a probe, and always called one."""
    fact = {"status": OBSERVED, "value": value, "source": source}
    if declare_side:
        fact["observed_by"] = side
    return fact


def _observe_app_id_in_both_places(
    provenance: dict,
    value: str = APP_ID,
    *,
    side: str = OBSERVATION_SIDE_CLIENT,
) -> None:
    """
    Record the client-observed application id in **both** places that hold it.

    The run-level application id is the application id of the EVM sandbox stage
    of the same invocation: the two are one fact in two places. A probe that
    patches only the run-level copy builds an artifact that contradicts itself,
    and the strict consumer refuses such an artifact by design.
    """
    fact = _observed_fact(value, SOURCE_CLIENT_APP_ID, side=side)
    block = provenance["modal_invocation_provenance"]
    block["modal_app_id"] = dict(fact)
    block["stages"][STAGE]["app_id"] = dict(fact)


def _build_provenance(tmp_path: Path) -> tuple[dict, Path]:
    """
    Build a provenance block from the real producer and write its artifact.

    The artifact is written to ``tmp_path`` and the provenance refers to it, so
    the digests of the provenance can be recomputed against real bytes.
    """
    envelope = _producer_envelope()
    response = {
        "stage": STAGE,
        "modal_runtime": envelope,
        "worker_observed": {"note": "the response of the production producer"},
    }
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=True,
        response_received=True,
        provider_response=response,
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime",
        response_source="the response of the production producer",
        requested_fields=("app_id", "function_call_id", "container_id"),
    )
    artifact_path, artifact_ref = write_stage_evidence_artifact(
        tmp_path,
        capture,
        target_id=TARGET_ID,
        correlation_id="corr-closure-probe",
    )
    stage_facts = build_stage_identity_facts(capture, evidence_ref=artifact_ref)
    provenance = {
        "modal_invocation_provenance": {
            "modal_app_id": stage_facts["app_id"],
            "client_observed": _client_block(),
            "target_id": TARGET_ID,
            "correlation_id": "corr-closure-probe",
            "stages": {
                STAGE: build_modal_stage_provenance(
                    function_name="verify_exploit_remote",
                    resource="CPU",
                    attempted=True,
                    evidence_ref=artifact_ref,
                    **stage_facts,
                ),
            },
        }
    }
    return provenance, artifact_path


def _rebuild_digests(provenance: dict, artifact_path: Path) -> None:
    """Recompute every digest the provenance states from the bytes on disk."""
    data = artifact_path.read_bytes()
    digest = sha256_bytes(data)
    length = len(data)

    def _fix(ref) -> None:
        if isinstance(ref, dict) and ref.get("path"):
            ref["sha256"] = digest
            ref["byte_length"] = length

    block = provenance["modal_invocation_provenance"]
    run_app = block.get("modal_app_id")
    if isinstance(run_app, dict):
        _fix(run_app.get("evidence_ref"))
    for stage in (block.get("stages") or {}).values():
        if not isinstance(stage, dict):
            continue
        _fix(stage.get("evidence_ref"))
        for key in ("app_id", "function_call_id", "container_id"):
            fact = stage.get(key)
            if isinstance(fact, dict):
                _fix(fact.get("evidence_ref"))


def _rewrite_artifact(artifact_path: Path) -> Path:
    """Rewrite the artifact with a different byte layout."""
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact_path.write_bytes(
        json.dumps(payload, indent=4, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    return artifact_path


def _artifact(baseline_id, target_id, status, *, verdict=None, detected=False, **kwargs):
    """One target execution artifact."""
    return TargetExecutionArtifact(
        baseline_id=baseline_id,
        target_id=target_id,
        target_name=target_id,
        status=status,
        security_verdict=verdict,
        detected=detected,
        **kwargs,
    )


def _ground_truth() -> dict:
    return {
        "T1": GroundTruth(contract_id="T1", is_vulnerable=True),
        "T2": GroundTruth(contract_id="T2", is_vulnerable=False),
    }


# =============================================================================
# P0 - the fail-closed evaluator leak
# =============================================================================

@pytest.mark.parametrize("status", INCOMPLETE_STATUSES)
@pytest.mark.parametrize("verdict", NEGATIVE_VERDICTS)
@pytest.mark.parametrize("raw_detected", [False, True])
def test_a_run_that_did_not_complete_is_never_a_negative_finding(status, verdict, raw_detected):
    """
    The defect of the P0: a target whose execution did not complete was
    serialized as ``detected: false``. It has to be ``None``.
    """
    artifact = _artifact(
        "b", "T1", status, verdict=verdict, detected=raw_detected, verified_breaches=1
    )
    result = evaluate_baseline_run("b", "B", [artifact], _ground_truth())

    detail = result.details[0]
    assert detail["detected"] is None
    assert detail["detection_state"] == DETECTION_STATE_NOT_EVALUATED
    assert detail["verified_breaches"] == 0
    assert detail["replayed_breaches"] == 0
    # The state of the execution stays visible and distinct.
    assert detail["status"] == status.value
    assert detail["security_verdict"] == verdict

    # The report record of the same target states the same thing.
    record = result.target_artifacts[0]
    assert record["detected"] is None
    assert record["detection_state"] == DETECTION_STATE_NOT_EVALUATED
    assert record["verified_breaches"] == 0
    # The raw claim of the producer is preserved - it is not presented as a finding.
    assert record["producer_detected"] is raw_detected
    assert record["producer_verified_breaches"] == 1


@pytest.mark.parametrize("status", INCOMPLETE_STATUSES)
def test_a_run_that_did_not_complete_is_never_a_negative_finding_without_a_verdict(status):
    """The same rule without any verdict at all."""
    artifact = _artifact("b", "T1", status)
    result = evaluate_baseline_run("b", "B", [artifact], _ground_truth())
    assert result.details[0]["detected"] is None
    assert result.details[0]["detection_state"] == DETECTION_STATE_NOT_EVALUATED


def test_a_mixed_baseline_keeps_the_failed_target_out_of_the_findings():
    """A mixed baseline: the metrics stay None, the failed target has no finding."""
    artifacts = [
        _artifact("b", "T1", ExecutionStatus.SUCCESS, detected=True),
        _artifact("b", "T2", ExecutionStatus.FAILED, verdict="COMPILATION_ERROR"),
    ]
    result = evaluate_baseline_run("b", "B", artifacts, _ground_truth())

    assert result.status == ExecutionStatus.INCOMPLETE
    assert result.precision is None
    assert result.recall is None
    assert result.f1_score is None
    assert result.true_positives is None
    assert result.false_negatives is None

    by_target = {d["target_id"]: d for d in result.details}
    assert by_target["T1"]["detected"] is True
    assert by_target["T1"]["detection_state"] == DETECTION_STATE_POSITIVE
    assert by_target["T2"]["detected"] is None
    assert by_target["T2"]["detection_state"] == DETECTION_STATE_NOT_EVALUATED


@pytest.mark.parametrize("verdict", NEGATIVE_VERDICTS)
def test_a_completed_run_keeps_its_negative_verdict(verdict):
    """
    The fix does not hollow out the verdict semantics: a **completed** run with a
    negative verdict stays a negative finding.
    """
    artifact = _artifact("b", "T1", ExecutionStatus.SUCCESS, verdict=verdict, detected=True)
    result = evaluate_baseline_run("b", "B", [artifact], _ground_truth())

    detail = result.details[0]
    assert detail["detected"] is False
    assert detail["detection_state"] == DETECTION_STATE_NEGATIVE
    # The baseline stays scorable - the execution completed.
    assert result.status == ExecutionStatus.SUCCESS
    assert result.precision is not None


def test_a_completed_run_keeps_its_own_detection():
    """A completed run without a negative verdict keeps the detection of the producer."""
    positive = _artifact("b", "T1", ExecutionStatus.SUCCESS, detected=True)
    negative = _artifact("b", "T2", ExecutionStatus.SUCCESS, detected=False)

    result = evaluate_baseline_run("b", "B", [positive, negative], _ground_truth())
    by_target = {d["target_id"]: d for d in result.details}
    assert by_target["T1"]["detected"] is True
    assert by_target["T1"]["detection_state"] == DETECTION_STATE_POSITIVE
    assert by_target["T2"]["detected"] is False
    assert by_target["T2"]["detection_state"] == DETECTION_STATE_NEGATIVE
    # The confusion matrix agrees with the report.
    assert result.true_positives == 1
    assert result.true_negatives == 1


def test_an_infrastructure_failure_is_not_a_negative_finding():
    """
    A completed execution whose verdict says that the **audit itself** failed
    produced no valid conclusion: it is not evaluated, not a negative finding.
    """
    artifact = _artifact("b", "T1", ExecutionStatus.SUCCESS, verdict="INFRA_ERROR")
    result = evaluate_baseline_run("b", "B", [artifact], _ground_truth())

    detail = result.details[0]
    assert detail["detected"] is None
    assert detail["detection_state"] == DETECTION_STATE_NOT_EVALUATED
    # A baseline with a target without a valid evaluation is not scorable.
    assert result.status == ExecutionStatus.INCOMPLETE
    assert result.precision is None
    assert "without a valid evaluation" in (result.status_reason or "")


def test_the_resolver_is_the_single_source_of_the_detection():
    """The report and the confusion matrix read the very same resolver."""
    artifact = _artifact("b", "T1", ExecutionStatus.FAILED, verdict="COMPILATION_ERROR")
    assert resolve_detection(artifact) == (None, DETECTION_STATE_NOT_EVALUATED)

    artifact = _artifact("b", "T1", ExecutionStatus.SUCCESS, verdict="SAFE_RUN")
    assert resolve_detection(artifact) == (False, DETECTION_STATE_NEGATIVE)

    artifact = _artifact("b", "T1", ExecutionStatus.SUCCESS, detected=True)
    assert resolve_detection(artifact) == (True, DETECTION_STATE_POSITIVE)


# =============================================================================
# P1 - the run-level observation side
# =============================================================================

def test_the_strict_consumer_accepts_a_client_observed_run_level_application_id(tmp_path):
    """
    The P0 of the strict mode: a valid client-observed application id passes.

    The application id is recorded in both places that hold it - the run-level
    fact and the copy of the EVM sandbox stage - because they are one fact in
    two places.
    """
    provenance, _ = _build_provenance(tmp_path)
    _observe_app_id_in_both_places(provenance)

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert ok, error


@pytest.mark.parametrize(
    "label,fact",
    [
        ("missing_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, declare_side=False)),
        ("null_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side=None)),
        ("unknown_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side="oracle")),
        ("worker_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_WORKER)),
        ("legacy_flat_value", APP_ID),
    ],
)
def test_the_strict_consumer_rejects_a_run_level_application_id_without_the_client_side(
    tmp_path, label, fact
):
    """A missing, a null, an unknown, a worker-side and a flat claim all fail."""
    provenance, _ = _build_provenance(tmp_path)
    provenance["modal_invocation_provenance"]["modal_app_id"] = fact

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert not ok, f"the strict consumer accepts the {label} run-level application id"
    assert error


def test_the_strict_consumer_rejects_a_missing_run_level_application_id(tmp_path):
    """A run that records no application id at all fails in the strict mode."""
    provenance, _ = _build_provenance(tmp_path)
    provenance["modal_invocation_provenance"].pop("modal_app_id", None)

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert not ok
    assert error


def test_the_strict_consumer_rejects_a_run_level_application_id_of_an_unknown_status(tmp_path):
    """An unknown status of the run-level fact fails."""
    provenance, _ = _build_provenance(tmp_path)
    provenance["modal_invocation_provenance"]["modal_app_id"] = {
        "status": "MAYBE",
        "value": APP_ID,
    }

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert not ok
    assert error


def test_the_rejection_of_the_run_level_side_comes_from_the_side_rule_and_not_from_a_digest(tmp_path):
    """
    The artifact is rewritten and the digests are **recomputed** from the bytes
    on disk: the correctly sided fact is accepted and the wrong side is refused
    by the side rule alone.
    """
    provenance, artifact_path = _build_provenance(tmp_path)
    _observe_app_id_in_both_places(provenance)
    artifact_path = _rewrite_artifact(artifact_path)
    _rebuild_digests(provenance, artifact_path)

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert ok, error

    provenance["modal_invocation_provenance"]["modal_app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_WORKER
    )
    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert not ok
    assert "digest" not in (error or "").lower()


def test_the_compatibility_path_still_accepts_the_side_less_run_level_application_id(tmp_path):
    """
    The artifacts of Iterations 14-20 carry a flat, side-less run-level
    application id: the compatibility path keeps reading them.
    """
    provenance, _ = _build_provenance(tmp_path)
    provenance["modal_invocation_provenance"]["modal_app_id"] = APP_ID
    provenance["modal_invocation_provenance"]["stages"][STAGE] = {
        "attempted": True,
        "function_name": "verify_exploit_remote",
        "resource": "CPU",
        "app_id": APP_ID,
        "function_call_id": FUNCTION_CALL_ID,
        "container_id": CONTAINER_ID,
    }

    ok, error = validate_modal_invocation_provenance(provenance)
    assert ok, error


def test_the_helper_is_additive_and_opt_in():
    """Without ``strict`` the helper restricts nothing."""
    assert validate_run_level_application_id(APP_ID) == (True, None)
    assert validate_run_level_application_id(None) == (True, None)
    ok, error = validate_run_level_application_id(APP_ID, strict=True)
    assert not ok and error


def test_the_billing_cross_check_still_compares_the_run_level_application_id(tmp_path):
    """The billing cross-check of the run-level application id is not weakened."""
    provenance, _ = _build_provenance(tmp_path)
    provenance["modal_invocation_provenance"]["modal_app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT
    )

    matched = cross_check_app_ids(provenance, [APP_ID])
    assert matched["status"] == "PASSED"
    scopes = {record["scope"]: record for record in matched["comparisons"]}
    assert scopes["modal_app_id"]["observed_app_id"] == APP_ID
    assert scopes["modal_app_id"]["status"] == "MATCHED"

    mismatched = cross_check_app_ids(provenance, ["ap-someOtherAppId"])
    assert mismatched["status"] == "FAILED"


def test_the_strict_consumer_still_rejects_a_stage_fact_with_the_wrong_side(tmp_path):
    """The rule of the stages is preserved - the fix touches the run level only."""
    provenance, _ = _build_provenance(tmp_path)
    provenance["modal_invocation_provenance"]["stages"][STAGE]["app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_WORKER
    )

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert not ok
    assert error


def test_the_client_block_rule_is_preserved(tmp_path):
    """A client observation inside a worker envelope stays refused."""
    from benchmarks.evidence_integrity import validate_runtime_identity_envelope

    envelope = _producer_envelope()
    envelope["app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT
    )
    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert error


# =============================================================================
# The vertical chains
# =============================================================================

def test_the_successful_vertical_chain_holds_end_to_end(tmp_path):
    """
    producer → capture → evidence artifact → strict validator → billing join →
    manifests → evaluator → report.
    """
    provenance, artifact_path = _build_provenance(tmp_path)
    _observe_app_id_in_both_places(provenance)

    # 1. the evidence artifact exists and its digest is the digest of the bytes
    assert artifact_path.is_file()
    assert file_sha256(artifact_path) == provenance["modal_invocation_provenance"]["stages"][
        STAGE
    ]["evidence_ref"]["sha256"]

    # 2. the strict consumer accepts the chain
    ok, error = validate_modal_invocation_provenance(
        provenance, known_app_ids=[APP_ID], evidence_root=tmp_path, strict_sources=True
    )
    assert ok, error

    # 3. the client block is client-side
    ok, error = validate_client_observed_facts(
        provenance["modal_invocation_provenance"]["client_observed"], strict_sources=True
    )
    assert ok, error

    # 4. the billing join attributes the invocation
    join = cross_check_app_ids(provenance, [APP_ID])
    assert join["status"] == "PASSED"

    # 5. the evaluator and the report state the finding
    artifact = _artifact("b", "T1", ExecutionStatus.SUCCESS, detected=True)
    result = evaluate_baseline_run("b", "B", [artifact], _ground_truth())
    assert result.status == ExecutionStatus.SUCCESS
    assert result.details[0]["detected"] is True
    assert result.details[0]["detection_state"] == DETECTION_STATE_POSITIVE
    assert result.target_artifacts[0]["detection_state"] == DETECTION_STATE_POSITIVE


def test_the_failure_vertical_chain_keeps_the_failure_visible(tmp_path):
    """
    The same chain with a failed execution: the failure is reported as a failure
    everywhere and never as a negative finding.
    """
    provenance, _ = _build_provenance(tmp_path)
    _observe_app_id_in_both_places(provenance)
    ok, error = validate_modal_invocation_provenance(
        provenance, known_app_ids=[APP_ID], evidence_root=tmp_path, strict_sources=True
    )
    assert ok, error

    artifact = _artifact(
        "b",
        "T1",
        ExecutionStatus.FAILED,
        verdict="EXECUTION_FAILURE",
        unavailable_reason="the sandbox worker died",
        verified_breaches=0,
    )
    result = evaluate_baseline_run("b", "B", [artifact], _ground_truth())

    assert result.status == ExecutionStatus.FAILED
    assert result.precision is None
    detail = result.details[0]
    assert detail["status"] == "FAILED"
    assert detail["security_verdict"] == "EXECUTION_FAILURE"
    assert detail["detected"] is None
    assert detail["detection_state"] == DETECTION_STATE_NOT_EVALUATED
    record = result.target_artifacts[0]
    assert record["detected"] is None
    assert record["detection_state"] == DETECTION_STATE_NOT_EVALUATED


def test_the_report_of_the_real_runner_states_the_detection_state(tmp_path):
    """The report of the real runner carries the state of every target."""
    import shutil

    from benchmarks.benchmark_runner import AegisBenchmarkSuite

    # The suite writes its report next to the dataset - the dataset is copied
    # into the temporary directory so that the test does not touch the
    # checkout.
    dataset_dir = tmp_path / "dataset"
    dataset_dir.mkdir(parents=True, exist_ok=True)
    dataset_path = dataset_dir / "benchmark_dataset.json"
    shutil.copyfile(_ROOT / "benchmarks" / "benchmark_dataset.json", dataset_path)

    suite = AegisBenchmarkSuite(
        dataset_path=dataset_path, artifacts_dir=tmp_path / "artifacts"
    )
    report = suite.run_benchmark(
        mode="smoke",
        baselines_to_run=["baseline_1"],
        save_results=True,
    )

    baselines = report["baselines"]
    assert baselines, "the smoke run produced no baseline"
    for baseline_id, baseline in baselines.items():
        for detail in baseline["details"]:
            assert detail["detection_state"] in (
                DETECTION_STATE_POSITIVE,
                DETECTION_STATE_NEGATIVE,
                DETECTION_STATE_NOT_EVALUATED,
            )
            if detail["status"] != "SUCCESS":
                assert detail["detected"] is None
        for record in baseline["target_artifacts"]:
            assert record["detection_state"] in (
                DETECTION_STATE_POSITIVE,
                DETECTION_STATE_NEGATIVE,
                DETECTION_STATE_NOT_EVALUATED,
            )
            if record["status"] != "SUCCESS":
                assert record["detected"] is None
        # The two views of a target agree with each other.
        details_by_id = {d["target_id"]: d for d in baseline["details"]}
        for record in baseline["target_artifacts"]:
            detail = details_by_id[record["target_id"]]
            assert record["detected"] == detail["detected"]
            assert record["detection_state"] == detail["detection_state"]
        assert baseline_id


# =============================================================================
# The compatibility path and the historical evidence
# =============================================================================

def test_the_registry_is_not_changed_by_the_fix():
    """The registry of the fields is exactly what it was."""
    assert PROVIDER_OBSERVATION_SOURCES["function_call_id"]["side"] == OBSERVATION_SIDE_WORKER
    assert PROVIDER_OBSERVATION_SOURCES["app_id"]["side"] == OBSERVATION_SIDE_CLIENT
    assert PROVIDER_OBSERVATION_SOURCES["app_page_url"]["side"] == OBSERVATION_SIDE_CLIENT
    assert PROVIDER_OBSERVATION_SOURCES["container_id"]["side"] == OBSERVATION_SIDE_CLIENT
    assert SOURCE_WORKER_FUNCTION_CALL_ID == "modal.current_function_call_id()"
    assert SOURCE_CLIENT_APP_ID and SOURCE_CLIENT_APP_PAGE_URL and SOURCE_CLIENT_CONTAINER_ID


def test_the_side_less_provider_fact_stays_valid_without_the_strict_mode():
    """A side-less fact of the compatibility path is not restricted."""
    fact = _observed_fact(FUNCTION_CALL_ID, SOURCE_WORKER_FUNCTION_CALL_ID, declare_side=False)
    assert validate_provider_observation_source("function_call_id", fact) == (True, None)
    ok, error = validate_provider_observation_source(
        "function_call_id", fact, require_side=True
    )
    assert not ok and error


# =============================================================================
# The follow-up - the contradiction rule and the presentation rules
# =============================================================================

@pytest.mark.parametrize(
    "label,run_fact,stage_fact",
    [
        (
            "the_stage_could_not_observe_the_application_id",
            _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT),
            None,
        ),
        (
            "the_two_copies_state_another_application_id",
            _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT),
            _observed_fact("ap-0000000000000000000", SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT),
        ),
    ],
)
def test_the_strict_consumer_rejects_a_run_level_application_id_that_contradicts_the_stage_copy(
    tmp_path, label, run_fact, stage_fact
):
    """
    The run-level application id is the application id of the EVM sandbox stage
    of the same invocation: one artifact may not state two different
    application ids for one invocation.
    """
    provenance, _ = _build_provenance(tmp_path)
    block = provenance["modal_invocation_provenance"]
    block["modal_app_id"] = run_fact
    if stage_fact is not None:
        block["stages"][STAGE]["app_id"] = stage_fact

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert not ok, f"the strict consumer accepts the case {label!r}"
    assert error


def test_an_absence_claim_is_not_compared_with_the_stage_copy(tmp_path):
    """
    An absence claim states that the value could not be observed - the strict
    mode does not side-check an absence claim either.

    The stage copy may carry a **client-side** observation of the application id
    while the run-level copy states that the **worker** could not read it: the
    two statements are compatible, and the artifacts of Iteration 21 and the
    probes of Iteration 23 have exactly that shape.
    """
    provenance, _ = _build_provenance(tmp_path)
    block = provenance["modal_invocation_provenance"]
    block["stages"][STAGE]["app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT
    )

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert ok, error


def test_the_compatibility_path_still_accepts_a_contradicting_run_level_application_id(tmp_path):
    """
    The contradiction rule belongs to the strict mode only: the artifacts of
    Iterations 14-20 keep being read exactly as before.
    """
    provenance, _ = _build_provenance(tmp_path)
    block = provenance["modal_invocation_provenance"]
    block["modal_app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT
    )
    block["stages"][STAGE]["app_id"] = _observed_fact(
        "ap-0000000000000000000", SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT
    )

    ok, error = validate_modal_invocation_provenance(provenance, evidence_root=tmp_path)
    assert ok, error


def test_the_strict_consumer_rejects_a_not_available_run_level_fact_that_carries_a_value(tmp_path):
    """An absence claim states that the value could not be observed."""
    provenance, _ = _build_provenance(tmp_path)
    fact = dict(provenance["modal_invocation_provenance"]["modal_app_id"])
    fact["value"] = APP_ID
    provenance["modal_invocation_provenance"]["modal_app_id"] = fact

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=tmp_path, strict_sources=True
    )
    assert not ok
    assert error


def test_the_two_views_of_a_target_agree_about_the_breach_counters():
    """
    The detail row and the report record use one rule, and a report never shows
    a breach count next to a target that found nothing.
    """
    artifact = TargetExecutionArtifact(
        baseline_id="baseline_closure",
        target_id="T1",
        target_name="T1",
        status=ExecutionStatus.SUCCESS,
        detected=False,
        security_verdict="CHEATCODE_DETECTED",
        verified_breaches=1,
        replayed_breaches=1,
        candidates_generated=2,
    )
    result = evaluate_baseline_run(
        "baseline_closure", "B", [artifact], {"T1": GroundTruth(contract_id="T1", is_vulnerable=False)}
    )

    detail = result.details[0]
    record = result.target_artifacts[0]
    assert detail["verified_breaches"] == record["verified_breaches"] == 0
    assert detail["replayed_breaches"] == record["replayed_breaches"] == 0
    # The raw claim of the producer is preserved - it is never presented as a
    # finding, but it is never lost either.
    assert record["producer_verified_breaches"] == 1
    assert record["producer_replayed_breaches"] == 1
    # The raw claim of the detection equals the presented one here, so there is
    # nothing to preserve separately.
    assert "producer_detected" not in record
    assert result.verified_finding_rate == 0.0


def test_the_raw_claim_of_the_producer_is_preserved_whenever_it_differs():
    """A negative verdict does not swallow the claim the producer made."""
    artifact = TargetExecutionArtifact(
        baseline_id="baseline_closure",
        target_id="T1",
        target_name="T1",
        status=ExecutionStatus.SUCCESS,
        detected=True,
        security_verdict="CHEATCODE_DETECTED",
        verified_breaches=1,
        replayed_breaches=0,
    )
    result = evaluate_baseline_run(
        "baseline_closure", "B", [artifact], {"T1": GroundTruth(contract_id="T1", is_vulnerable=False)}
    )

    record = result.target_artifacts[0]
    assert record["detected"] is False
    assert record["detection_state"] == DETECTION_STATE_NEGATIVE
    assert record["producer_detected"] is True
    assert record["producer_verified_breaches"] == 1


def test_a_run_without_a_target_is_not_scorable():
    """A run with no target has no metric at all."""
    result = evaluate_baseline_run("baseline_closure", "B", [], {})

    assert result.status == ExecutionStatus.INCOMPLETE
    assert result.status_reason
    assert result.total_targets == 0
    assert result.precision is None
    assert result.candidates_per_verified_finding is None
    assert result.details == []
    assert result.target_artifacts == []
