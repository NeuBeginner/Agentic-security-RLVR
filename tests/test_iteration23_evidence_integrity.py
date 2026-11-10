"""
tests/test_iteration23_evidence_integrity.py
=============================================

Iteration 23 (PR #12 follow-up) - the strict **stage** validation must use the
**registered** observation side of the field.

The Iteration 22 review kept one narrow validator gap open as a P1:

* the strict stage loop of ``validate_modal_invocation_provenance()`` calls
  ``validate_provider_observation_source(key, fact, expected_side="worker",
  require_side=True)`` for **every** key of ``PROVIDER_OBSERVATION_SOURCES``;
* the registry registers ``function_call_id`` as worker-side, but ``app_id``,
  ``app_page_url`` and ``container_id`` as **client**-side.

A correctly typed, correctly sourced and correctly sided client-side stage fact
was therefore rejected as contradictory - the strict consumer overrode the
registry with a hardcoded side.

This suite proves the fix:

* the strict consumer **accepts** a stage that holds a worker-observed
  ``function_call_id`` and client-observed ``app_id``, ``app_page_url`` and
  ``container_id``;
* the strict consumer **rejects** the same facts with a missing, a ``null``, an
  unknown or the wrong side - the cross-side direction stays closed;
* the separate rule that a **worker runtime-identity envelope** may never carry
  a client observation is preserved;
* the **actual** strict provenance consumer is exercised through the whole
  chain (producer -> stage facts -> serialized artifact -> consumer), and the
  artifact digests are **recomputed** after every tampering, so a rejection can
  only come from the side rule and not from a stale digest;
* the compatibility path is untouched.
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
    canonical_json_bytes,
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
    _ROOT / "benchmarks" / "evidence" / "iteration23_change_impact_matrix.md"
)
CI_WORKFLOW = _ROOT / ".github" / "workflows" / "ci.yml"

STAGE = "evm_sandbox"
TARGET_ID = "ITER23-01"

#: The provider-issued identifiers the tests work with.
FUNCTION_CALL_ID = "fc-01M71H7789CATYCWNEG05916Y3"
APP_ID = "ap-gW7GDdh9OlSqjL2tRnB1oJ"
APP_PAGE_URL = f"https://modal.com/id/{APP_ID}"
CONTAINER_ID = "ta-01M71H78SAWD0JF71CFPA0QTRR"

#: The registered client-side fields, with their registered source and value.
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
        correlation_id="corr-iteration23-test",
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
            "correlation_id": "corr-iteration23-test",
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


def _stage(provenance: Dict[str, Any]) -> Dict[str, Any]:
    """The stage of the provenance block."""
    return provenance["modal_invocation_provenance"]["stages"][STAGE]


def _rebuild_digests(provenance: Dict[str, Any], artifact_path: Path) -> None:
    """
    Recompute every digest the provenance states.

    The tampering tests have to prove that the rejection comes from the side
    rule and not from a stale digest - so the digests are recomputed from the
    bytes on disk after every tampering.
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


def _rewrite_artifact(artifact_path: Path) -> Path:
    """
    Rewrite the stage evidence artifact with a different byte layout.

    The content stays the same, the bytes do not: the digest of the file
    changes, so a provenance that still holds the old digest is stale - which
    is exactly what the tests have to rule out as the reason of a rejection.
    """
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact_path.write_bytes(
        json.dumps(payload, indent=4, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    return artifact_path


def _recompute_payload_digests(artifact: Dict[str, Any]) -> None:
    """
    Recompute the digests the artifact states about its own payload.

    The artifact describes the bytes of its payload; a tampered payload has to
    be described again, otherwise the artifact is refused for its own digest
    and the refusal says nothing about the rule under test.
    """
    metadata = artifact.get("provider_response_metadata")
    if not isinstance(metadata, dict):
        return

    response = artifact.get("provider_response")
    if response is not None:
        response_bytes = canonical_json_bytes(response)
        metadata["response_sha256"] = sha256_bytes(response_bytes)
        metadata["response_byte_length"] = len(response_bytes)

    envelope = artifact.get("runtime_identity")
    if envelope is not None:
        envelope_bytes = canonical_json_bytes(envelope)
        metadata["runtime_identity_sha256"] = sha256_bytes(envelope_bytes)
        metadata["runtime_identity_byte_length"] = len(envelope_bytes)


def _write_artifact(tmp_path: Path, artifact: Dict[str, Any]) -> Path:
    """Write the (possibly tampered) artifact and return its path."""
    path = tmp_path / f"{TARGET_ID}_stage_evidence_{STAGE}.json"
    path.write_bytes(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    return path


def _client_observed_stage_facts() -> Dict[str, Any]:
    """The client-side facts a stage may carry - each with its registered side."""
    return {
        "app_id": _fact(
            APP_ID,
            SOURCE_CLIENT_APP_ID,
            side=OBSERVATION_SIDE_CLIENT,
        ),
        "app_page_url": _fact(
            APP_PAGE_URL,
            SOURCE_CLIENT_APP_PAGE_URL,
            side=OBSERVATION_SIDE_CLIENT,
        ),
        "container_id": _fact(
            CONTAINER_ID,
            SOURCE_CLIENT_CONTAINER_ID,
            side=OBSERVATION_SIDE_CLIENT,
        ),
    }


# ===========================================================================
# 1) The defect is closed: the registered side is honoured
# ===========================================================================

def test_iteration23_the_strict_consumer_accepts_a_client_observed_app_id_in_a_stage(
    tmp_path, monkeypatch
):
    """
    The defect itself: a correctly sided client fact was rejected.

    ``app_id`` is registered as a client-side field. A stage that records the
    application id the **client** observed names the client side, the
    registered source and the provider's shape - and the strict consumer has
    to accept it.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage["app_id"] = _fact(
        APP_ID,
        SOURCE_CLIENT_APP_ID,
        side=OBSERVATION_SIDE_CLIENT,
    )

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration23_the_strict_consumer_accepts_a_client_observed_container_id_in_a_stage(
    tmp_path, monkeypatch
):
    """The container id is registered as a client-side field as well."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage["container_id"] = _fact(
        CONTAINER_ID,
        SOURCE_CLIENT_CONTAINER_ID,
        side=OBSERVATION_SIDE_CLIENT,
    )

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration23_the_strict_consumer_accepts_a_client_observed_app_page_url_in_a_stage(
    tmp_path, monkeypatch
):
    """
    The app page URL is registered as a client-side field too.

    The shape of a stage that the producer writes does not carry an
    ``app_page_url`` - the field lives in the client block and in the runtime
    envelope. The consumer nevertheless **checks** the field when a stage
    carries it, and it has to accept the correctly sided fact.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage["app_page_url"] = _fact(
        APP_PAGE_URL,
        SOURCE_CLIENT_APP_PAGE_URL,
        side=OBSERVATION_SIDE_CLIENT,
    )

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration23_the_strict_consumer_accepts_a_worker_observed_function_call_id_in_a_stage(
    tmp_path, monkeypatch
):
    """The worker field of the registry still works."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage["function_call_id"] = _fact(
        FUNCTION_CALL_ID,
        SOURCE_WORKER_FUNCTION_CALL_ID,
        side=OBSERVATION_SIDE_WORKER,
    )

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration23_the_registry_is_the_single_source_of_truth_for_the_stage_side(
    tmp_path, monkeypatch
):
    """
    Every registered field is accepted with **its own** registered side.

    The loop is generic over the registry, so this test is generic too: no
    field of the registry may be accepted with a side other than the one it
    registers.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)

    for field_name, registered in PROVIDER_OBSERVATION_SOURCES.items():
        provenance = _provenance(captured)
        stage = _stage(provenance)
        stage[field_name] = _fact(
            {
                "function_call_id": FUNCTION_CALL_ID,
                "app_id": APP_ID,
                "app_page_url": APP_PAGE_URL,
                "container_id": CONTAINER_ID,
            }[field_name],
            registered["source"],
            side=registered["side"],
        )

        ok, error = validate_modal_invocation_provenance(
            provenance,
            evidence_root=tmp_path,
            strict_sources=True,
        )
        assert ok, f"{field_name}: {error}"


def test_iteration23_the_strict_consumer_accepts_a_client_observed_app_id_with_the_billing_cross_check(
    tmp_path, monkeypatch
):
    """
    The accepted client fact is the one the billing cross-check compares.

    The cross-check runs over the same stage facts, so the accepted fact has to
    be comparable with the raw billing export.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage["app_id"] = _fact(
        APP_ID,
        SOURCE_CLIENT_APP_ID,
        side=OBSERVATION_SIDE_CLIENT,
    )

    ok, error = validate_modal_invocation_provenance(
        provenance,
        known_app_ids=[APP_ID],
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


# ===========================================================================
# 2) The rules that stay closed
# ===========================================================================

@pytest.mark.parametrize("field_name,source,value", CLIENT_FIELDS)
def test_iteration23_the_strict_consumer_rejects_a_missing_side(
    tmp_path, monkeypatch, field_name, source, value
):
    """A fact that names no side at all does not say who observed it."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage[field_name] = _fact(value, source, declare_side=False)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")


@pytest.mark.parametrize("field_name,source,value", CLIENT_FIELDS)
def test_iteration23_the_strict_consumer_rejects_a_null_side(
    tmp_path, monkeypatch, field_name, source, value
):
    """``observed_by: null`` is the omission in another shape."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage[field_name] = _fact(value, source, side=None)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")


@pytest.mark.parametrize("field_name,source,value", CLIENT_FIELDS)
def test_iteration23_the_strict_consumer_rejects_an_unknown_side(
    tmp_path, monkeypatch, field_name, source, value
):
    """A fact may name only a known side."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage[field_name] = _fact(value, source, side="oracle")

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")


@pytest.mark.parametrize("field_name,source,value", CLIENT_FIELDS)
def test_iteration23_the_strict_consumer_rejects_a_worker_side_on_a_client_field(
    tmp_path, monkeypatch, field_name, source, value
):
    """
    The cross-side direction stays closed.

    The registered side of ``app_id``, ``app_page_url`` and ``container_id`` is
    the client side - a stage that presents one of them as a worker
    observation is rejected.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage[field_name] = _fact(value, source, side=OBSERVATION_SIDE_WORKER)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")


def test_iteration23_the_strict_consumer_rejects_a_client_side_on_the_worker_field(
    tmp_path, monkeypatch
):
    """The worker field of the registry may not be presented as client-side."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage["function_call_id"] = _fact(
        FUNCTION_CALL_ID,
        SOURCE_WORKER_FUNCTION_CALL_ID,
        side=OBSERVATION_SIDE_CLIENT,
    )

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")


def test_iteration23_a_worker_envelope_may_not_carry_a_client_observation():
    """
    The separate rule survives: a worker envelope is worker-side.

    The fix of this iteration changes the **stage** validation only. The
    runtime-identity envelope of the worker is still worker-side by
    construction, and a client observation inside it is still rejected.
    """
    envelope = {
        "app_id": _fact(
            APP_ID,
            SOURCE_CLIENT_APP_ID,
            side=OBSERVATION_SIDE_CLIENT,
        )
    }

    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


def test_iteration23_the_strict_consumer_rejects_a_worker_envelope_with_a_client_observation(
    tmp_path, monkeypatch
):
    """
    The same rule inside the consumer chain.

    The stage evidence artifact holds the runtime-identity envelope of the
    worker; an envelope that carries a client observation is refused, and the
    digests are recomputed so that the refusal cannot come from a stale
    digest.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    artifact = json.loads(captured["artifact_path"].read_text(encoding="utf-8"))
    for envelope in (
        artifact.get("runtime_identity"),
        (artifact.get("provider_response") or {}).get("modal_runtime"),
    ):
        if isinstance(envelope, dict):
            envelope["app_id"] = _fact(
                APP_ID,
                SOURCE_CLIENT_APP_ID,
                side=OBSERVATION_SIDE_CLIENT,
            )
    # The worker reported the application id, so the absence record of the
    # field does not belong to the artifact any more.
    artifact["absence_records"] = [
        record
        for record in artifact.get("absence_records", [])
        if record.get("field") != "app_id"
    ]
    _recompute_payload_digests(artifact)
    artifact_path = _write_artifact(tmp_path, artifact)
    _rebuild_digests(provenance, artifact_path)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")


def test_iteration23_the_client_block_still_rejects_a_worker_side():
    """The client block keeps its own rule - it is client-side."""
    block = _client_block()
    block["app_id"] = _fact(
        APP_ID,
        SOURCE_CLIENT_APP_ID,
        side=OBSERVATION_SIDE_WORKER,
    )

    ok, error = validate_client_observed_facts(block, strict_sources=True)
    assert not ok
    assert "side" in (error or "")


# ===========================================================================
# 3) The chain, with recomputed digests
# ===========================================================================

def test_iteration23_the_producer_stage_artifact_and_consumer_chain_holds(
    tmp_path, monkeypatch
):
    """
    The whole path holds: producer -> stage facts -> artifact -> consumer.

    The producer is the real one; the facts are the ones it wrote; the artifact
    is the file on disk; the consumer is the strict provenance consumer.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    # The producer's own fact names the worker side.
    assert _stage(provenance)["function_call_id"]["observed_by"] == OBSERVATION_SIDE_WORKER

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration23_the_client_side_facts_are_accepted_with_recomputed_digests(
    tmp_path, monkeypatch
):
    """
    The acceptance does not depend on a stale digest.

    The artifact is rewritten with a different byte layout, the digests of the
    provenance are recomputed from the bytes on disk, and the consumer still
    accepts the stage with the client-side facts.

    Without the recomputation the artifact would be refused for its digest -
    that is the control of the next test.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    for field_name, fact in _client_observed_stage_facts().items():
        stage[field_name] = fact

    artifact_path = _rewrite_artifact(captured["artifact_path"])
    _rebuild_digests(provenance, artifact_path)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration23_a_stale_digest_is_refused_before_the_side_rule(
    tmp_path, monkeypatch
):
    """
    The control: a stale digest is refused on its own.

    Without the recomputation the rewritten artifact does not match the digest
    the provenance states - so the rejection of the next test cannot be
    attributed to a stale digest.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    for field_name, fact in _client_observed_stage_facts().items():
        stage[field_name] = fact

    _rewrite_artifact(captured["artifact_path"])

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "digest" in (error or "").lower()


def test_iteration23_the_strict_consumer_rejects_the_wrong_side_with_recomputed_digests(
    tmp_path, monkeypatch
):
    """
    The rejection comes from the side rule - not from a stale digest.

    The client-observed application id of the stage is presented as a worker
    observation, the artifact is rewritten, the digests are recomputed - and
    the consumer still refuses the artifact. The positive control then restores
    the client side - with the same digests - and the very same artifact is
    accepted.
    """
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    provenance = _provenance(captured)

    stage = _stage(provenance)
    stage["app_id"] = _fact(
        APP_ID,
        SOURCE_CLIENT_APP_ID,
        side=OBSERVATION_SIDE_WORKER,
    )

    artifact_path = _rewrite_artifact(captured["artifact_path"])
    _rebuild_digests(provenance, artifact_path)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert not ok
    assert "side" in (error or "")
    assert "digest" not in (error or "").lower()

    # The positive control: the side is back, the digests are the same.
    stage["app_id"] = _fact(
        APP_ID,
        SOURCE_CLIENT_APP_ID,
        side=OBSERVATION_SIDE_CLIENT,
    )

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


# ===========================================================================
# 4) The compatibility path
# ===========================================================================

def test_iteration23_the_compatibility_path_is_untouched(tmp_path, monkeypatch):
    """
    The non-strict path reads the side-less facts of Iterations 14-20.

    No side is inferred and none is backfilled: the compatibility path simply
    accepts the old shape, and only there.
    """
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


def test_iteration23_the_historical_evidence_stays_valid():
    """The published evidence of the earlier iterations still passes."""
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


def test_iteration23_the_published_capture_of_iteration_21_passes_the_strict_mode():
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
# 5) The registry and the documentation of the iteration
# ===========================================================================

def test_iteration23_the_registry_names_a_side_for_every_field():
    """Every registered field names the side it may be observed from."""
    for field_name, registered in PROVIDER_OBSERVATION_SOURCES.items():
        assert registered["side"] in (OBSERVATION_SIDE_WORKER, OBSERVATION_SIDE_CLIENT)
        assert field_name in ("app_id", "app_page_url", "container_id", "function_call_id")


def test_iteration23_the_helper_accepts_the_registered_side_of_every_field():
    """The helper itself accepts the registered side of every field."""
    values = {
        "function_call_id": FUNCTION_CALL_ID,
        "app_id": APP_ID,
        "app_page_url": APP_PAGE_URL,
        "container_id": CONTAINER_ID,
    }
    for field_name, registered in PROVIDER_OBSERVATION_SOURCES.items():
        fact = _fact(
            values[field_name],
            registered["source"],
            side=registered["side"],
        )

        ok, error = validate_provider_observation_source(
            field_name,
            fact,
            expected_side=registered["side"],
            require_side=True,
        )
        assert ok, f"{field_name}: {error}"


def test_iteration23_the_change_impact_matrix_documents_the_iteration():
    """The matrix states the boundary and the rule of the iteration."""
    if not CHANGE_IMPACT_MATRIX.is_file():
        pytest.skip("the change impact matrix of Iteration 23 is not committed")
    matrix = CHANGE_IMPACT_MATRIX.read_text(encoding="utf-8")
    assert "Iteration 23" in matrix
    assert "no live modal call" in matrix.lower()
    assert "observed_by" in matrix
    assert "strict" in matrix.lower()


def test_iteration23_the_ci_workflow_runs_the_new_suite_and_the_new_validator():
    """The workflow runs the Iteration 23 suite and the Iteration 23 validator."""
    if not CI_WORKFLOW.is_file():
        pytest.skip("the CI workflow is not committed")
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "tests/test_iteration23_evidence_integrity.py" in workflow
    assert "python -m benchmarks.validate_iteration23_evidence --check" in workflow


def test_iteration23_the_code_sha_of_the_iteration_is_an_ancestor_of_head():
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
