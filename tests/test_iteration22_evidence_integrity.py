"""
tests/test_iteration22_evidence_integrity.py
=============================================

Iteration 22 (PR #12 follow-up) - the strict mode must require the
**observation side** of every observed identity fact.

The Iteration 21 review kept one narrow validator gap open as a P1:

* ``validate_observation_side()`` returns success when ``observed_by`` is
  absent, and ``validate_provider_observation_source()`` compares the side
  with the registered one only when it is non-null. A worker fact with the
  registered source ``modal.current_function_call_id()``, a valid ``fc-...``
  value and **no** observation side therefore passes the strict validation.

This suite proves the fix:

* the strict mode rejects an observed fact that names no side - missing,
  ``null``, unknown or contradictory - for the worker field and for every
  client field;
* the strict mode still accepts a valid worker or client fact;
* the compatibility path (the default) still accepts the side-less facts of
  Iterations 14-20 - no side is ever inferred or backfilled;
* the **actual** strict provenance consumer rejects the omission while the
  artifact digests are recomputed, so the rejection cannot come from a stale
  digest.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    MODAL_IDENTITY_FIELDS,
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
    not_available,
    observed,
    sha256_bytes,
    validate_client_observed_facts,
    validate_modal_invocation_provenance,
    validate_provider_observation_source,
    validate_runtime_identity_envelope,
    write_stage_evidence_artifact,
)

CHANGE_IMPACT_MATRIX = (
    _ROOT / "benchmarks" / "evidence" / "iteration22_change_impact_matrix.md"
)
CI_WORKFLOW = _ROOT / ".github" / "workflows" / "ci.yml"

STAGE = "evm_sandbox"
TARGET_ID = "ITER22-01"

#: The provider-issued identifiers the tests work with.
FUNCTION_CALL_ID = "fc-01M71H7789CATYCWNEG05916Y3"
APP_ID = "ap-gW7GDdh9OlSqjL2tRnB1oJ"
APP_PAGE_URL = f"https://modal.com/id/{APP_ID}"
CONTAINER_ID = "ta-01M71H78SAWD0JF71CFPA0QTRR"

#: The registered client-side facts, with their registered source and value.
CLIENT_FIELDS = (
    ("app_id", SOURCE_CLIENT_APP_ID, APP_ID),
    ("app_page_url", SOURCE_CLIENT_APP_PAGE_URL, APP_PAGE_URL),
    ("container_id", SOURCE_CLIENT_CONTAINER_ID, CONTAINER_ID),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fact(
    value: str,
    source: str,
    *,
    side: Optional[str] = None,
    declare_side: bool = True,
) -> Dict[str, Any]:
    """
    An observed fact.

    ``side`` is the side the fact names; ``declare_side=False`` leaves the
    field out completely - the omission this iteration is about.
    """
    fact: Dict[str, Any] = {"status": OBSERVED, "value": value, "source": source}
    if declare_side:
        fact["observed_by"] = side
    return fact


def _producer_envelope(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    """Run the **real** production producer and return the envelope it built."""
    import modal
    import modal_app

    monkeypatch.setattr(
        modal,
        "current_function_call_id",
        lambda: FUNCTION_CALL_ID,
        raising=False,
    )
    for name in ("MODAL_WORKER_ID", "HOSTNAME", "MODAL_TASK_ID"):
        monkeypatch.delenv(name, raising=False)

    return modal_app.capture_modal_runtime_identity()


def _capture_and_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Dict[str, Any]:
    """Run the real producer and write its stage evidence artifact."""
    envelope = _producer_envelope(monkeypatch)
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
        requested_fields=MODAL_IDENTITY_FIELDS,
    )

    artifact_path, artifact_ref = write_stage_evidence_artifact(
        tmp_path,
        capture,
        target_id=TARGET_ID,
        correlation_id="corr-iteration22-test",
    )
    return {
        "envelope": envelope,
        "capture": capture,
        "artifact_path": artifact_path,
        "artifact_ref": artifact_ref,
    }


def _client_block() -> Dict[str, Any]:
    """The client-observed block of a run - every fact names the client side."""
    return {
        "app_id": observed(
            APP_ID,
            source=SOURCE_CLIENT_APP_ID,
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
        "app_page_url": observed(
            APP_PAGE_URL,
            source=SOURCE_CLIENT_APP_PAGE_URL,
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
        "container_id": not_available(
            "the provider was not asked in this test",
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
    }


def _provenance(captured: Dict[str, Any]) -> Dict[str, Any]:
    """The provenance block of the capture - the artifact a reader sees."""
    stage_facts = build_stage_identity_facts(
        captured["capture"],
        evidence_ref=captured["artifact_ref"],
    )
    return {
        "modal_invocation_provenance": {
            "modal_app_id": stage_facts["app_id"],
            "client_observed": _client_block(),
            "target_id": TARGET_ID,
            "correlation_id": "corr-iteration22-test",
            "stages": {
                STAGE: build_modal_stage_provenance(
                    function_name="verify_exploit_remote",
                    resource="CPU",
                    attempted=True,
                    evidence_ref=captured["artifact_ref"],
                    **stage_facts,
                ),
            },
        }
    }


def _rebuild_digests(provenance: Dict[str, Any], artifact_path: Path) -> None:
    """
    Recompute every digest the provenance states.

    The tampering tests have to prove that the rejection comes from the
    missing side and not from a stale digest - so the digests are recomputed
    from the bytes on disk after every tampering.
    """
    data = artifact_path.read_bytes()
    digest = sha256_bytes(data)
    length = len(data)

    def _fix(ref: Any) -> None:
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


def _strip_side(artifact: Dict[str, Any], provenance: Dict[str, Any]) -> None:
    """Remove the observation side of the function-call id everywhere."""
    for envelope in (
        artifact.get("runtime_identity"),
        (artifact.get("provider_response") or {}).get("modal_runtime"),
    ):
        if isinstance(envelope, dict):
            fact = envelope.get("function_call_id")
            if isinstance(fact, dict):
                fact.pop("observed_by", None)
    stage = provenance["modal_invocation_provenance"]["stages"][STAGE]
    fact = stage.get("function_call_id")
    if isinstance(fact, dict):
        fact.pop("observed_by", None)


def _write_artifact(tmp_path: Path, artifact: Dict[str, Any]) -> Path:
    """Write the (possibly tampered) artifact and return its path."""
    path = tmp_path / f"{TARGET_ID}_stage_evidence_{STAGE}.json"
    path.write_bytes(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    return path


# ===========================================================================
# 1) The defect: the strict mode accepts a fact that names no side
# ===========================================================================

def test_iteration22_a_worker_fact_without_a_side_is_rejected_in_the_strict_mode():
    """
    The defect itself: the registered source and a valid value are not enough.

    The fact names the registered worker-side source and carries a valid
    ``fc-...`` value - and it does not say who observed it. The strict mode
    has to reject it.
    """
    envelope = {
        "function_call_id": _fact(
            FUNCTION_CALL_ID,
            SOURCE_WORKER_FUNCTION_CALL_ID,
            declare_side=False,
        )
    }

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


@pytest.mark.parametrize("field_name,source,value", CLIENT_FIELDS)
def test_iteration22_a_client_fact_without_a_side_is_rejected(field_name, source, value):
    """The same omission is rejected for every client-side field."""
    envelope = {field_name: _fact(value, source, declare_side=False)}

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


def test_iteration22_a_null_side_is_rejected_in_the_strict_mode():
    """``observed_by: null`` is the omission in another shape."""
    envelope = {
        "function_call_id": _fact(
            FUNCTION_CALL_ID,
            SOURCE_WORKER_FUNCTION_CALL_ID,
            side=None,
        )
    }

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


def test_iteration22_an_unknown_side_is_rejected_in_the_strict_mode():
    """A fact may name only a known side."""
    envelope = {
        "function_call_id": _fact(
            FUNCTION_CALL_ID,
            SOURCE_WORKER_FUNCTION_CALL_ID,
            side="oracle",
        )
    }

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


def test_iteration22_a_client_side_on_a_worker_field_is_rejected():
    """A client observation may never be presented as a worker observation."""
    envelope = {
        "function_call_id": _fact(
            FUNCTION_CALL_ID,
            SOURCE_WORKER_FUNCTION_CALL_ID,
            side=OBSERVATION_SIDE_CLIENT,
        )
    }

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


def test_iteration22_a_worker_side_on_a_client_field_is_rejected():
    """The registered side of a client field is the client side."""
    envelope = {
        "app_id": _fact(
            APP_ID,
            SOURCE_CLIENT_APP_ID,
            side=OBSERVATION_SIDE_WORKER,
        )
    }

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


def test_iteration22_the_helper_rejects_the_omission_when_the_side_is_required():
    """The helper itself refuses a side-less fact in the strict mode."""
    fact = _fact(FUNCTION_CALL_ID, SOURCE_WORKER_FUNCTION_CALL_ID, declare_side=False)

    ok, error = validate_provider_observation_source(
        "function_call_id",
        fact,
        expected_side=OBSERVATION_SIDE_WORKER,
        require_side=True,
    )
    assert not ok
    assert "side" in (error or "")


def test_iteration22_the_client_block_rejects_a_side_less_observed_fact():
    """The client block does not accept an observed fact without a side."""
    block = _client_block()
    block["app_id"] = _fact(APP_ID, SOURCE_CLIENT_APP_ID, declare_side=False)

    ok, error = validate_client_observed_facts(block, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


# ===========================================================================
# 2) The valid facts still pass
# ===========================================================================

def test_iteration22_a_valid_worker_fact_is_accepted_in_the_strict_mode():
    """The producer's own fact - the one that names the worker side."""
    envelope = {
        "function_call_id": _fact(
            FUNCTION_CALL_ID,
            SOURCE_WORKER_FUNCTION_CALL_ID,
            side=OBSERVATION_SIDE_WORKER,
        )
    }

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert ok, error


@pytest.mark.parametrize("field_name,source,value", CLIENT_FIELDS)
def test_iteration22_a_valid_client_fact_is_accepted_in_the_strict_mode(
    field_name, source, value
):
    """The client facts of the registry are accepted in the strict mode."""
    fact = _fact(value, source, side=OBSERVATION_SIDE_CLIENT)

    ok, error = validate_provider_observation_source(
        field_name,
        fact,
        expected_side=OBSERVATION_SIDE_CLIENT,
        require_side=True,
    )
    assert ok, error


def test_iteration22_the_real_producer_passes_the_strict_mode(monkeypatch):
    """The envelope of the real producer satisfies the strict mode."""
    envelope = _producer_envelope(monkeypatch)

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert ok, error

    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope.get(field_name)
        if isinstance(fact, dict) and fact.get("status") == OBSERVED:
            assert fact.get("observed_by") == OBSERVATION_SIDE_WORKER, field_name


# ===========================================================================
# 3) The compatibility path: the side is never inferred or backfilled
# ===========================================================================

def test_iteration22_a_side_less_fact_stays_valid_in_the_compatibility_path():
    """The default path still reads the side-less facts of Iterations 14-20."""
    envelope = {
        "function_call_id": _fact(
            FUNCTION_CALL_ID,
            SOURCE_WORKER_FUNCTION_CALL_ID,
            declare_side=False,
        )
    }

    ok, error = validate_runtime_identity_envelope(envelope)
    assert ok, error

    ok, error = validate_provider_observation_source(
        "function_call_id",
        envelope["function_call_id"],
    )
    assert ok, error


def test_iteration22_the_legacy_flat_stage_value_stays_valid_in_the_compatibility_path():
    """A legacy flat value names no side - it stays valid, but only there."""
    provenance = {
        "modal_invocation_provenance": {
            "modal_app_id": APP_ID,
            "client_observed": _client_block(),
            "target_id": TARGET_ID,
            "stages": {
                STAGE: {
                    "attempted": True,
                    "function_name": "verify_exploit_remote",
                    "resource": "CPU",
                    "app_id": APP_ID,
                    "function_call_id": FUNCTION_CALL_ID,
                    "container_id": CONTAINER_ID,
                }
            },
        }
    }

    ok, error = validate_modal_invocation_provenance(provenance)
    assert ok, error


def test_iteration22_the_legacy_flat_stage_value_is_rejected_in_the_strict_mode():
    """The strict mode does not accept a value that names no side."""
    provenance = {
        "modal_invocation_provenance": {
            "modal_app_id": APP_ID,
            "client_observed": _client_block(),
            "target_id": TARGET_ID,
            "stages": {
                STAGE: {
                    "attempted": True,
                    "function_name": "verify_exploit_remote",
                    "resource": "CPU",
                    "app_id": APP_ID,
                    "function_call_id": FUNCTION_CALL_ID,
                    "container_id": CONTAINER_ID,
                }
            },
        }
    }

    ok, error = validate_modal_invocation_provenance(provenance, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


def test_iteration22_the_historical_evidence_of_iterations_20_and_21_stays_valid():
    """The published captures still satisfy their own validators."""
    from benchmarks.validate_iteration20_evidence import (
        DEFAULT_EVIDENCE_DIR as ITER20_DIR,
        _validate_iteration20,
    )
    from benchmarks.validate_iteration21_evidence import (
        DEFAULT_EVIDENCE_DIR as ITER21_DIR,
        _validate_iteration21,
    )

    iter20_dir = _ROOT / ITER20_DIR
    if not (iter20_dir / "capture_record.json").is_file():
        pytest.skip("the capture of Iteration 20 is not committed")
    outcome = _validate_iteration20(evidence_dir=iter20_dir, code_sha=None)
    assert outcome["errors"] == [], outcome["errors"]

    iter21_dir = _ROOT / ITER21_DIR
    if not (iter21_dir / "capture_record.json").is_file():
        pytest.skip("the capture of Iteration 21 is not committed")
    outcome = _validate_iteration21(evidence_dir=iter21_dir, code_sha=None)
    assert outcome["errors"] == [], outcome["errors"]


def test_iteration22_the_published_capture_of_iteration_21_passes_the_strict_mode():
    """The strict rule does not break the evidence that is already published."""
    from benchmarks.validate_iteration21_evidence import DEFAULT_EVIDENCE_DIR as ITER21_DIR

    evidence_dir = _ROOT / ITER21_DIR
    record_path = evidence_dir / "capture_record.json"
    if not record_path.is_file():
        pytest.skip("the capture of Iteration 21 is not committed")

    record = json.loads(record_path.read_text(encoding="utf-8"))

    ok, error = validate_runtime_identity_envelope(
        record["runtime_identity"],
        strict_sources=True,
    )
    assert ok, error

    ok, error = validate_modal_invocation_provenance(
        record["provenance"]["artifact"],
        evidence_root=evidence_dir,
        strict_sources=True,
    )
    assert ok, error


# ===========================================================================
# 4) The actual strict provenance consumer
# ===========================================================================

def test_iteration22_the_strict_consumer_accepts_the_complete_artifact(tmp_path, monkeypatch):
    """The whole path holds: producer -> artifact -> provenance consumer."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration22_the_strict_consumer_rejects_a_stage_fact_without_a_side(
    tmp_path, monkeypatch
):
    """The consumer rejects the omission in the facts a reader sees."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = provenance["modal_invocation_provenance"]["stages"][STAGE]
    stage["function_call_id"].pop("observed_by", None)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")


def test_iteration22_the_strict_consumer_rejects_the_omission_with_recomputed_digests(
    tmp_path, monkeypatch
):
    """
    The rejection comes from the missing side - not from a stale digest.

    The artifact is tampered with, the digests are **recomputed** from the
    bytes on disk, and the consumer still refuses the artifact. The positive
    control then restores the side - with the same digests - and the very
    same artifact is accepted.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error

    artifact = json.loads(captured["artifact_path"].read_text(encoding="utf-8"))
    _strip_side(artifact, provenance)
    artifact_path = _write_artifact(tmp_path, artifact)
    _rebuild_digests(provenance, artifact_path)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")

    # The positive control: the side is back, the digests are the same.
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    for envelope in (
        artifact.get("runtime_identity"),
        (artifact.get("provider_response") or {}).get("modal_runtime"),
    ):
        if isinstance(envelope, dict):
            fact = envelope.get("function_call_id")
            if isinstance(fact, dict):
                fact["observed_by"] = OBSERVATION_SIDE_WORKER
    stage = provenance["modal_invocation_provenance"]["stages"][STAGE]
    stage["function_call_id"]["observed_by"] = OBSERVATION_SIDE_WORKER
    artifact_path = _write_artifact(tmp_path, artifact)
    _rebuild_digests(provenance, artifact_path)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration22_the_strict_consumer_rejects_a_client_fact_without_a_side(
    tmp_path, monkeypatch
):
    """The client block of the consumer is checked as well."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    block = provenance["modal_invocation_provenance"]["client_observed"]
    block["app_page_url"] = _fact(
        APP_PAGE_URL,
        SOURCE_CLIENT_APP_PAGE_URL,
        declare_side=False,
    )

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")


# ===========================================================================
# 5) The registry and the documentation of the iteration
# ===========================================================================

def test_iteration22_the_registry_names_a_side_for_every_field():
    """Every registered field names the side it may be observed from."""
    for field_name, registered in PROVIDER_OBSERVATION_SOURCES.items():
        assert registered["side"] in (OBSERVATION_SIDE_WORKER, OBSERVATION_SIDE_CLIENT)
        assert field_name in ("app_id", "app_page_url", "container_id", "function_call_id")


def test_iteration22_the_change_impact_matrix_documents_the_iteration():
    """The matrix states the boundary and the rule of the iteration."""
    if not CHANGE_IMPACT_MATRIX.is_file():
        pytest.skip("the change impact matrix of Iteration 22 is not committed")
    matrix = CHANGE_IMPACT_MATRIX.read_text(encoding="utf-8")
    assert "Iteration 22" in matrix
    assert "no live modal call" in matrix.lower()
    assert "observed_by" in matrix
    assert "strict" in matrix.lower()


def test_iteration22_the_ci_workflow_runs_the_new_suite_and_the_new_validator():
    """The workflow runs the Iteration 22 suite and the Iteration 22 validator."""
    if not CI_WORKFLOW.is_file():
        pytest.skip("the CI workflow is not committed")
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "tests/test_iteration22_evidence_integrity.py" in workflow
    assert "python -m benchmarks.validate_iteration22_evidence --check" in workflow


def test_iteration22_the_code_sha_of_the_iteration_is_an_ancestor_of_head():
    """The commits of this iteration belong to the history of the branch."""
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    assert head

    matrix_commit = subprocess.run(
        ["git", "log", "--format=%H", "-1", "--", str(CHANGE_IMPACT_MATRIX)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    assert matrix_commit, "the change impact matrix is not committed"

    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", matrix_commit, head],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ancestor.returncode == 0
