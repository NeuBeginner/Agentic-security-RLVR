"""
tests/test_iteration19_evidence_integrity.py
============================================

Iteration 19 (PR #12 follow-up) - the live, CPU-only Modal runtime smoke test.

Iterations 14-18 hardened the evidence contract of the benchmark run, but every
published validation artifact up to now was produced **offline**: the
"producer rehearsal" executes the real producer path against faithful
reconstructions of worker responses. A rehearsal proves that the contract
holds; it cannot prove that a **real Modal worker** is reached and reports its
own runtime identity.

Iteration 19 closes that gap with the smallest possible live surface - one
CPU-only function, one invocation, one artifact - and checks it with the
**unchanged** Iteration 18 validators:

* the stage evidence artifact satisfies ``validate_stage_evidence_artifact``;
* the runtime-identity envelope satisfies ``validate_runtime_identity_envelope``;
* the envelope is the one the captured response carries at the declared source;
* the four flags of the stage describe exactly one state;
* every identifier is provider-issued and none is a synthetic identity;
* the digest of the artifact is the digest of the bytes on disk;
* the run is bound to the commit it was made from;
* every field the runtime did not expose carries the exact reason;
* the billed usage is provider-backed or explicitly unavailable - never an
  estimate;
* no GPU was allocated and no deployed production worker was touched.

The tests that need the live artifacts skip - with an explicit reason - while
the artifacts of the run are not committed yet. The tests of the contract
itself always run.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    MODAL_APP_ID_RE,
    MODAL_CONTAINER_ID_RE,
    MODAL_FUNCTION_CALL_ID_RE,
    MODAL_IDENTITY_FIELDS,
    MODAL_IMAGE_ID_RE,
    NOT_AVAILABLE,
    OBSERVED,
    STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
    STAGE_STATE_TABLE,
    StageResponseCapture,
    build_stage_evidence_artifact,
    canonical_json_bytes,
    sha256_bytes,
    validate_runtime_identity_envelope,
    validate_stage_evidence_artifact,
)
from benchmarks.validate_iteration19_evidence import (  # noqa: E402
    STAGE,
    TARGET_ID,
    _validate_iteration19,
    main,
)

EVIDENCE_DIR = _ROOT / "benchmarks" / "evidence" / "iteration19_cpu_smoke"
RECORD_PATH = EVIDENCE_DIR / "invocation_record.json"
ARTIFACT_PATH = EVIDENCE_DIR / f"{TARGET_ID}_stage_evidence_{STAGE}.json"
VALIDATION_EVIDENCE = _ROOT / "benchmarks" / "evidence" / "iteration19_validation_evidence.json"
CHANGE_IMPACT_MATRIX = _ROOT / "benchmarks" / "evidence" / "iteration19_change_impact_matrix.md"
SMOKE_APP_SOURCE = _ROOT / "benchmarks" / "modal_cpu_smoke_app.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _live_artifacts() -> Dict[str, Any]:
    """The committed artifacts of the live run - or an explicit skip."""
    if not RECORD_PATH.is_file() or not ARTIFACT_PATH.is_file():
        pytest.skip(
            "the live CPU-only evidence of Iteration 19 is not committed yet - the "
            "artifacts of the run are published with the evidence commit"
        )
    record = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    artifact = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))
    return {"record": record, "artifact": artifact}


def _check_by_name(outcome: Dict[str, Any], name: str) -> Dict[str, Any]:
    for check in outcome["checks"]:
        if check["check"] == name:
            return check
    raise AssertionError(f"the validator does not run the check {name!r}")


def _revalidate(
    tmp_path: Path,
    *,
    record_mutator: Optional[Callable[[Dict[str, Any]], None]] = None,
    artifact_mutator: Optional[Callable[[Dict[str, Any]], None]] = None,
    keep_recorded_digest: bool = False,
) -> Dict[str, Any]:
    """
    Run the Iteration 19 validator over a copy of the live artifacts.

    The copy may be mutated - that is how the adversarial tests prove that the
    validator really rejects a broken artifact and does not merely accept the
    published one. With ``keep_recorded_digest`` the record keeps the digest of
    the published artifact, so a tampered artifact is caught twice: by the
    contract of the artifact and by the digest of its bytes.
    """
    live = _live_artifacts()
    record = json.loads(json.dumps(live["record"]))
    artifact = json.loads(json.dumps(live["artifact"]))

    if record_mutator is not None:
        record_mutator(record)
    if artifact_mutator is not None:
        artifact_mutator(artifact)

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    artifact_bytes = json.dumps(
        artifact, indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    (evidence_dir / ARTIFACT_PATH.name).write_bytes(artifact_bytes)

    if not keep_recorded_digest:
        # The record must claim the digest of the bytes that are on disk now.
        record["evidence_artifact"]["sha256"] = sha256_bytes(artifact_bytes)
        record["evidence_artifact"]["byte_length"] = len(artifact_bytes)
    (evidence_dir / RECORD_PATH.name).write_text(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8"
    )

    return _validate_iteration19(evidence_dir=evidence_dir, code_sha=None)


# ===========================================================================
# 1) The live invocation
# ===========================================================================

def test_iteration19_the_invocation_record_reports_a_successful_single_invocation():
    """The record must state that one live CPU-only invocation succeeded."""
    live = _live_artifacts()
    invocation = live["record"]["invocation"]

    assert invocation["attempted"] is True
    assert invocation["executed"] is True
    assert invocation["response_received"] is True
    assert invocation["runtime_envelope_received"] is True
    assert invocation["status"] == "SUCCEEDED"
    assert invocation["invocation_count"] == 1
    assert invocation["error"] is None
    assert invocation["started_at_utc"] and invocation["finished_at_utc"]


def test_iteration19_a_failed_invocation_is_recorded_as_a_failed_stage():
    """A failed invocation must be recorded as a failure, never as a success."""
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
        runtime_identity_source="",
        response_source="",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    artifact = build_stage_evidence_artifact(
        capture, target_id=TARGET_ID, correlation_id="iteration19-test"
    )

    flags = (
        artifact["attempted"],
        artifact["executed"],
        artifact["response_received"],
        artifact["runtime_envelope_received"],
    )
    assert STAGE_STATE_TABLE[flags] == "ATTEMPT_FAILED_NO_RESPONSE"
    assert artifact["provider_response"] is None
    assert artifact["provider_response_metadata"]["response_sha256"] is None
    assert artifact["provider_response_metadata"]["response_source"] == ""
    for record in artifact["absence_records"]:
        assert record["kind"] == "STAGE_ATTEMPT_FAILED_NO_RESPONSE"


# ===========================================================================
# 2) CPU-only, no production change
# ===========================================================================

def test_iteration19_the_app_declares_no_gpu_and_the_worker_observed_no_gpu_device():
    """The smoke app must request no GPU, and the worker must have seen none."""
    live = _live_artifacts()

    declared = live["record"]["modal"]["declared_resources"]
    assert declared["gpu"] is None
    assert declared["retries"] == 0
    assert declared["timeout"] <= 120

    source = SMOKE_APP_SOURCE.read_text(encoding="utf-8")
    assert "gpu=DECLARED_RESOURCES" in source
    assert '"gpu": None' in source

    evidence = live["record"]["gpu_statement"]["worker_observed_evidence"]
    assert evidence["gpu_device_exposed"] is False
    assert evidence["nvidia_device_nodes"] == []
    assert evidence["cuda_runtime_libraries"] == []
    assert evidence["nvidia_visible_devices_env"] is None
    assert evidence["cuda_visible_devices_env"] is None
    assert evidence["nvidia_smi_on_path"] is None


def test_iteration19_a_gpu_allocation_is_rejected(tmp_path):
    """A record that claims a GPU must be rejected by the validator."""
    outcome = _revalidate(
        tmp_path,
        record_mutator=lambda record: record["gpu_statement"].update(
            {"gpu_allocated": True, "gpu_requested": "H100"}
        ),
    )
    check = _check_by_name(outcome, "P1.11.zero_gpu_allocation")
    assert check["status"] == "FAILED"
    assert check["error"]


def test_iteration19_the_run_declares_an_ephemeral_app_and_no_production_change(tmp_path):
    """The run must state that it used an ephemeral app and changed nothing."""
    live = _live_artifacts()
    invocation = live["record"]["invocation"]

    assert invocation["deployment_kind"] == "ephemeral"
    assert "none" in invocation["production_change"].lower()
    assert "deploy" in invocation["production_change"].lower()

    outcome = _revalidate(tmp_path)
    check = _check_by_name(outcome, "P1.12.no_production_change")
    assert check["status"] == "PASSED"


# ===========================================================================
# 3) The provider-issued identifiers
# ===========================================================================

def test_iteration19_the_observed_identifiers_match_the_provider_shapes():
    """Every observed identifier must have the shape the provider issues."""
    live = _live_artifacts()
    identifiers = live["record"]["identifiers"]

    app_id = identifiers["app_id"]
    assert app_id["status"] == OBSERVED
    assert MODAL_APP_ID_RE.fullmatch(app_id["value"])
    assert app_id["source"]

    function_call_id = identifiers["function_call_id"]
    assert function_call_id["status"] == OBSERVED
    assert MODAL_FUNCTION_CALL_ID_RE.fullmatch(function_call_id["value"])

    container_id = identifiers["container_id"]
    assert container_id["status"] == OBSERVED
    assert MODAL_CONTAINER_ID_RE.fullmatch(container_id["value"])

    image_id = identifiers["image_id"]
    assert image_id["status"] == OBSERVED
    assert MODAL_IMAGE_ID_RE.fullmatch(image_id["value"])


def test_iteration19_the_worker_observed_identifiers_match_the_envelope():
    """A worker-observed identifier must be the one the worker observed."""
    live = _live_artifacts()
    identifiers = live["record"]["identifiers"]
    envelope = live["artifact"]["runtime_identity"]

    for field_name in ("function_call_id", "image_id"):
        fact = identifiers[field_name]
        assert fact["observed_by"] == "worker"
        assert fact["status"] == OBSERVED
        assert envelope[field_name]["status"] == OBSERVED
        assert fact["value"] == envelope[field_name]["value"]


def test_iteration19_a_synthetic_container_id_is_rejected(tmp_path):
    """A synthetic container identity must be rejected."""
    outcome = _revalidate(
        tmp_path,
        record_mutator=lambda record: record["identifiers"]["container_id"].update(
            {"value": "modal-cpu-0123456789ab"}
        ),
    )
    check = _check_by_name(outcome, "P1.6.provider_issued_identifiers")
    assert check["status"] == "FAILED"
    assert "synthetic" in check["error"]


# ===========================================================================
# 4) The response / envelope binding
# ===========================================================================

def test_iteration19_the_envelope_is_the_one_the_captured_response_carries():
    """The envelope must be the value the captured response carries."""
    live = _live_artifacts()
    artifact = live["artifact"]

    ok, error = validate_stage_evidence_artifact(artifact, expected_stage=STAGE)
    assert ok, error

    response = artifact["provider_response"]
    source = artifact["runtime_identity_source"]
    assert isinstance(response, dict)
    assert source in response
    assert canonical_json_bytes(response[source]) == canonical_json_bytes(
        artifact["runtime_identity"]
    )


def test_iteration19_a_detached_envelope_is_rejected(tmp_path):
    """An envelope that the captured response does not carry must be rejected."""
    outcome = _revalidate(
        tmp_path,
        artifact_mutator=lambda artifact: artifact.update(
            {"runtime_identity_source": "somewhere_else"}
        ),
    )
    check = _check_by_name(outcome, "P1.4.response_envelope_binding")
    assert check["status"] == "FAILED"
    assert "does not carry" in check["error"]


def test_iteration19_the_smoke_stage_is_in_the_state_with_a_runtime_envelope():
    """The live stage must be in the state that carries a runtime envelope."""
    live = _live_artifacts()
    artifact = live["artifact"]

    flags = (
        artifact["attempted"],
        artifact["executed"],
        artifact["response_received"],
        artifact["runtime_envelope_received"],
    )
    assert STAGE_STATE_TABLE[flags] == STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE


def test_iteration19_an_impossible_state_is_rejected():
    """A combination of flags that cannot happen must not be accepted."""
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=False,
        executed=True,
        response_received=True,
        provider_response={"a": 1},
        runtime_identity=None,
        runtime_identity_source="",
        response_source="test",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    artifact = build_stage_evidence_artifact(
        capture, target_id=TARGET_ID, correlation_id="iteration19-test"
    )
    flags = (
        artifact["attempted"],
        artifact["executed"],
        artifact["response_received"],
        artifact["runtime_envelope_received"],
    )
    assert flags not in STAGE_STATE_TABLE

    ok, error = validate_stage_evidence_artifact(artifact, expected_stage=STAGE)
    assert not ok
    assert "impossible state" in (error or "")


# ===========================================================================
# 5) The typed facts of the envelope
# ===========================================================================

def test_iteration19_the_envelope_carries_typed_facts_only():
    """Every identity field of the envelope must be a documented typed fact."""
    live = _live_artifacts()
    envelope = live["artifact"]["runtime_identity"]

    ok, error = validate_runtime_identity_envelope(envelope)
    assert ok, error

    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope[field_name]
        assert fact["status"] in (OBSERVED, NOT_AVAILABLE)
        if fact["status"] == OBSERVED:
            assert isinstance(fact["value"], str) and fact["value"].strip()
            assert fact["source"]
        else:
            assert fact["value"] is None
            assert fact["reason"].strip()


def test_iteration19_a_malformed_identity_fact_is_rejected():
    """A fact that is present but malformed must be an error, not an omission."""
    ok, error = validate_runtime_identity_envelope(
        {"container_id": {"status": OBSERVED, "value": None, "source": "x"}}
    )
    assert not ok
    assert "malformed" in (error or "")

    ok, error = validate_runtime_identity_envelope({"container_id": "some-id"})
    assert not ok
    assert "malformed" in (error or "")


# ===========================================================================
# 6) The digest of the artifact, verified from disk
# ===========================================================================

def test_iteration19_the_artifact_digest_matches_the_bytes_on_disk():
    """The recorded digest must be the digest of the stored bytes."""
    live = _live_artifacts()
    record = live["record"]

    data = ARTIFACT_PATH.read_bytes()
    assert sha256_bytes(data) == record["evidence_artifact"]["sha256"]
    assert len(data) == record["evidence_artifact"]["byte_length"]


def test_iteration19_a_tampered_artifact_is_rejected(tmp_path):
    """An artifact whose bytes were changed must be rejected."""
    outcome = _revalidate(
        tmp_path,
        artifact_mutator=lambda artifact: artifact["provider_response"][
            "smoke_payload"
        ].update({"smoke_result": "tampered"}),
        keep_recorded_digest=True,
    )
    contract = _check_by_name(outcome, "P1.2.stage_evidence_contract")
    assert contract["status"] == "FAILED"
    digest = _check_by_name(outcome, "P1.7.artifact_digest_from_disk")
    assert digest["status"] == "FAILED"
    assert "differs from the digest" in digest["error"]


# ===========================================================================
# 7) The worker-observed runtime metadata
# ===========================================================================

def test_iteration19_the_worker_observed_runtime_metadata_is_recorded():
    """The runtime metadata must be observed inside the container."""
    live = _live_artifacts()
    observed = live["record"]["worker_observed"]

    assert observed["python_version"]
    assert observed["platform"]
    assert observed["kernel_release"]
    assert observed["modal_sdk_version"]
    assert observed["modal_environment"]

    sdk_version = live["record"]["modal"]["sdk_version"]
    assert sdk_version and sdk_version.startswith("1.")


def test_iteration19_an_unexplained_missing_field_is_rejected(tmp_path):
    """A field that is not available must carry the reason why."""
    outcome = _revalidate(
        tmp_path,
        record_mutator=lambda record: record["identifiers"]["image_digest"].update(
            {"reason": ""}
        ),
    )
    check = _check_by_name(outcome, "P1.9.worker_observed_runtime_metadata")
    assert check["status"] == "FAILED"


def test_iteration19_the_billed_usage_is_provider_backed_or_explicitly_unavailable():
    """The billed usage is a provider fact or an explicit absence - never a guess."""
    live = _live_artifacts()
    billed = live["record"]["billed_usage"]

    assert billed["status"] in (OBSERVED, NOT_AVAILABLE)
    if billed["status"] == OBSERVED:
        assert billed["value"]["line_items"]
        assert billed["source"]
    else:
        assert billed["value"] is None
        assert billed["reason"].strip()


def test_iteration19_an_estimated_billed_usage_is_rejected(tmp_path):
    """A billed usage without a provider fact and without a reason is rejected."""
    outcome = _revalidate(
        tmp_path,
        record_mutator=lambda record: record["billed_usage"].update(
            {"status": "ESTIMATED", "value": 0.01, "reason": ""}
        ),
    )
    check = _check_by_name(outcome, "P1.10.billed_usage")
    assert check["status"] == "FAILED"


# ===========================================================================
# 8) The published validation artifact and CI
# ===========================================================================

def test_iteration19_the_validation_evidence_is_bound_to_the_code_sha():
    """The published validation evidence must name the code SHA it came from."""
    if not VALIDATION_EVIDENCE.is_file():
        pytest.skip("the validation artifact of Iteration 19 is not committed yet")

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    assert report["generator"] == "benchmarks/validate_iteration19_evidence.py"

    code_sha = report["code_sha"]
    assert isinstance(code_sha, str) and re.fullmatch(r"[0-9a-f]{40}", code_sha), code_sha

    exists = subprocess.run(
        ["git", "cat-file", "-t", code_sha],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert exists.returncode == 0, f"{code_sha} is not a commit of this repository"

    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", code_sha, "HEAD"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert ancestor.returncode == 0, (
        f"{code_sha} is not an ancestor of HEAD; the evidence must belong to this branch"
    )

    assert report["summary"]["overall_status"] == "PASSED"
    assert report["summary"]["checks_failed"] == 0


def test_iteration19_the_check_mode_detects_a_foreign_code_sha(tmp_path):
    """The --check mode must refuse a report that belongs to another commit."""
    if not VALIDATION_EVIDENCE.is_file():
        pytest.skip("the validation artifact of Iteration 19 is not committed yet")

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    report["code_sha"] = "0" * 40
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps(report), encoding="utf-8")

    exit_code = main(["--check", "--report", str(foreign), "--code-sha", "a" * 40])
    assert exit_code == 1


def test_iteration19_the_ci_workflow_runs_the_new_suite_and_the_new_validator():
    """CI must execute the Iteration 19 suite and the Iteration 19 validator."""
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "tests/test_iteration19_evidence_integrity.py" in ci
    assert "benchmarks.validate_iteration19_evidence" in ci


def test_iteration19_the_change_impact_matrix_documents_the_iteration():
    """The matrix must exist and must state the CPU-only boundary."""
    assert CHANGE_IMPACT_MATRIX.is_file()
    matrix = CHANGE_IMPACT_MATRIX.read_text(encoding="utf-8")
    assert "Iteration 19" in matrix
    assert "CPU-only" in matrix
    assert "no H100" in matrix
