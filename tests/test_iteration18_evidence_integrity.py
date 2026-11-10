"""
tests/test_iteration18_evidence_integrity.py
=============================================

Iteration 18 (PR #12 follow-up) - the captured response is bound to the
runtime envelope.

The Iteration 17 review found three remaining ways for an internally
self-consistent, SHA-256-valid artifact to misrepresent what the stage
actually returned:

1. the validator rejected ``response_received=True`` with a null payload, but
   not the inverse - ``response_received=False`` next to a stored provider
   response passed, and the response metadata always carried a digest, a byte
   length and a source that made a stage without a response look like a stage
   whose response was captured;
2. the check that binds the runtime-identity envelope to the captured response
   was inside ``if isinstance(provider_response, dict)`` - for a string, a
   list or a scalar payload the binding was skipped entirely, so a fabricated
   envelope passed;
3. a malformed identity fact in the envelope (``{"container_id":
   "some-id"}``, an unknown status, an observed fact with a null value) was
   treated as though the provider had simply omitted the field.

Iteration 18 therefore binds three descriptions of one event together:

* the flag ``response_received`` and the stored payload (both directions);
* the runtime-identity envelope and the captured response it comes from (for
  every shape of the payload);
* the schema of every identity fact the envelope carries.

The producer refuses to write an artifact in which they do not agree
(``EvidenceContractError``), and the validator rejects such an artifact even
when every digest in it is internally consistent.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    ABSENCE_PROVIDER_FIELD_OMITTED,
    MODAL_IDENTITY_FIELDS,
    NOT_AVAILABLE,
    OBSERVED,
    EvidenceContractError,
    StageResponseCapture,
    build_stage_evidence_artifact,
    canonical_json_bytes,
    classify_absence_kind,
    sha256_bytes,
    validate_runtime_identity_envelope,
    validate_stage_capture,
    validate_stage_evidence_artifact,
    write_stage_evidence_artifact,
)

VALIDATION_EVIDENCE = _ROOT / "benchmarks" / "evidence" / "iteration18_validation_evidence.json"
CHANGE_IMPACT_MATRIX = (
    _ROOT / "benchmarks" / "evidence" / "iteration18_change_impact_matrix.md"
)

APP_ID = "ap-EDUitOwWeMrIdYbTh4kB63"
FUNCTION_CALL_ID = "fc-8Hq2ZpQrVt3Lb"
CONTAINER_ID = "hokkglpxczflmxlcnxxg"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _runtime_identity(**overrides: Any) -> Dict[str, Any]:
    """A runtime-identity envelope exactly as the Modal workers return it."""
    identity: Dict[str, Any] = {
        "app_id": {
            "status": OBSERVED,
            "value": APP_ID,
            "source": "modal.running_app().app_id",
        },
        "function_call_id": {
            "status": OBSERVED,
            "value": FUNCTION_CALL_ID,
            "source": "modal.current_function_call_id()",
        },
        "container_id": {
            "status": OBSERVED,
            "value": CONTAINER_ID,
            "source": "MODAL_WORKER_ID of the running container",
        },
    }
    identity.update(overrides)
    return identity


def _capture(
    stage: str = "evm_sandbox",
    *,
    attempted: bool = True,
    executed: bool = True,
    response_received: bool = True,
    provider_response: Any = None,
    runtime_identity: Optional[Dict[str, Any]] = None,
    runtime_identity_source: str = "modal_runtime",
    requested_fields: Any = MODAL_IDENTITY_FIELDS,
) -> StageResponseCapture:
    """
    Build the capture of one stage.

    The capture keeps its flags, its payload and its envelope consistent with
    each other: a stage that received no response holds no payload, and a
    stage that holds no envelope names no source.
    """
    if provider_response is None and runtime_identity is not None:
        provider_response = {"modal_runtime": runtime_identity}
    if not response_received:
        provider_response = None
    if runtime_identity is None:
        runtime_identity_source = ""
    return StageResponseCapture(
        stage=stage,
        attempted=attempted,
        executed=executed,
        response_received=response_received,
        provider_response=provider_response,
        runtime_identity=runtime_identity,
        runtime_identity_source=runtime_identity_source,
        response_source=f"the response of the {stage} stage",
        requested_fields=tuple(requested_fields),
    )


def _recompute_digests(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Make the internal digests of a mutated artifact consistent again.

    The digest of the returned payload and the digest of the runtime-identity
    envelope are recomputed from the mutated content, so the artifact stays
    internally consistent and the validator can only reject it on the contract
    itself.

    A stage that received no response holds no payload and therefore carries
    no response digest either - the digest of the JSON literal ``null`` is not
    the digest of a captured response.
    """
    metadata = payload["provider_response_metadata"]
    provider_response = payload.get("provider_response")
    if provider_response is None:
        metadata["response_sha256"] = None
        metadata["response_byte_length"] = None
        metadata["response_source"] = ""
    else:
        provider_bytes = canonical_json_bytes(provider_response)
        metadata["response_sha256"] = sha256_bytes(provider_bytes)
        metadata["response_byte_length"] = len(provider_bytes)
        if not str(metadata.get("response_source") or "").strip():
            metadata["response_source"] = f"the response of the {payload.get('stage')} stage"
    runtime_identity = payload.get("runtime_identity")
    if runtime_identity is not None:
        runtime_bytes = canonical_json_bytes(runtime_identity)
        metadata["runtime_identity_sha256"] = sha256_bytes(runtime_bytes)
        metadata["runtime_identity_byte_length"] = len(runtime_bytes)
    else:
        metadata["runtime_identity_sha256"] = None
        metadata["runtime_identity_byte_length"] = None
    return payload


def _records_for(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The absence records the shared classifier derives from an artifact."""
    records: List[Dict[str, Any]] = []
    for field_name in MODAL_IDENTITY_FIELDS:
        kind = classify_absence_kind(
            attempted=bool(payload.get("attempted")),
            response_received=bool(payload.get("response_received")),
            requested_fields=payload.get("requested_fields") or (),
            runtime_identity=payload.get("runtime_identity"),
            field_name=field_name,
        )
        if kind is None:
            continue
        records.append(
            {
                "kind": kind,
                "field": field_name,
                "reason": f"the state of the stage makes this field {kind}",
            }
        )
    return records


def _artifact(capture: StageResponseCapture) -> Dict[str, Any]:
    """Build the artifact of one stage and keep it internally consistent."""
    payload = build_stage_evidence_artifact(
        capture, target_id="T-01", correlation_id="corr-test"
    )
    payload["absence_records"] = _records_for(payload)
    return _recompute_digests(payload)


def _validate(payload: Dict[str, Any], stage: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Validate an artifact against the stage it declares."""
    return validate_stage_evidence_artifact(
        payload, expected_stage=stage or payload.get("stage", "evm_sandbox")
    )


def _swap_envelope(payload: Dict[str, Any], envelope: Dict[str, Any]) -> Dict[str, Any]:
    """
    Put another envelope into the artifact **and** into the captured response.

    The binding between the two stays intact, so the artifact remains
    internally consistent: only the contract itself can reject it.
    """
    payload["runtime_identity"] = envelope
    payload["runtime_envelope_received"] = True
    payload["runtime_identity_source"] = "modal_runtime"
    provider_response = payload.get("provider_response")
    if isinstance(provider_response, dict):
        provider_response["modal_runtime"] = envelope
    payload["absence_records"] = _records_for(payload)
    return _recompute_digests(payload)


# ===========================================================================
# 1) Finding 1 - the response flag and the stored payload are one thing
# ===========================================================================

def test_iteration18_a_response_may_not_be_stored_next_to_the_no_response_flag():
    """
    The defect of Finding 1, as a regression test.

    The artifact says that the stage received no response, but it stores a
    provider response anyway. Every digest of the artifact is consistent - the
    contradiction is the only thing that gives the tampering away.
    """
    capture = _capture(
        "evm_sandbox",
        attempted=True,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    payload = _artifact(capture)
    assert payload["provider_response"] is None

    # The mutation: a stale payload next to the "no response" flag.
    payload["provider_response"] = {"verdict": "ok"}
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "claims that no response was received but holds a provider response" in error


def test_iteration18_a_response_flag_needs_a_payload():
    """The other direction: a response that was received has to be stored."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"verdict": "ok"},
        runtime_identity=None,
    )
    payload = _artifact(capture)
    payload["provider_response"] = None
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "claims that a response was received but holds none" in error


@pytest.mark.parametrize(
    "metadata_key",
    ["response_sha256", "response_byte_length", "response_source"],
)
def test_iteration18_the_response_metadata_may_not_imply_a_response(metadata_key: str):
    """
    A stage without a response has no response metadata.

    The metadata of a response describes a response that was really captured.
    A digest of the JSON literal ``null``, a byte length or a source would
    make a stage that received nothing look like a stage whose response was
    captured and hashed.
    """
    capture = _capture(
        "inference",
        attempted=True,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    payload = _artifact(capture)
    metadata = payload["provider_response_metadata"]

    if metadata_key == "response_sha256":
        metadata["response_sha256"] = sha256_bytes(canonical_json_bytes({"verdict": "ok"}))
    elif metadata_key == "response_byte_length":
        metadata["response_byte_length"] = 42
    else:
        metadata["response_source"] = "the response of the inference stage"

    ok, error = _validate(payload)
    assert ok is False
    assert "its response metadata implies that a response was captured" in error


def test_iteration18_the_producer_writes_no_response_metadata_when_no_response_was_captured():
    """The producer writes nothing at all about a response it never got."""
    capture = _capture(
        "inference",
        attempted=True,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    payload = _artifact(capture)
    metadata = payload["provider_response_metadata"]

    assert payload["provider_response"] is None
    assert metadata["response_sha256"] is None
    assert metadata["response_byte_length"] is None
    assert metadata["response_source"] == ""
    assert payload["runtime_identity_source"] == ""
    assert metadata["runtime_identity_sha256"] is None


def test_iteration18_a_captured_response_needs_its_source():
    """A stored payload has to say where it came from."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"verdict": "ok"},
        runtime_identity=None,
    )
    payload = _artifact(capture)
    payload["provider_response_metadata"]["response_source"] = ""

    ok, error = _validate(payload)
    assert ok is False
    assert "does not say where that response came from" in error


def test_iteration18_the_producer_refuses_a_contradictory_capture():
    """The producer refuses to write an artifact that contradicts itself."""
    contradictory = StageResponseCapture(
        stage="evm_sandbox",
        attempted=True,
        executed=False,
        response_received=False,
        provider_response={"verdict": "ok"},
        runtime_identity=None,
        runtime_identity_source="",
        response_source="the response of the evm_sandbox stage",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    with pytest.raises(EvidenceContractError) as excinfo:
        build_stage_evidence_artifact(
            contradictory, target_id="T-01", correlation_id="corr-test"
        )
    assert "claims that no response was received but the capture holds a payload" in str(
        excinfo.value
    )

    ok, error = validate_stage_capture(contradictory)
    assert ok is False
    assert "holds a payload" in error


def test_iteration18_the_producer_refuses_a_response_without_a_payload():
    """A capture that claims a response but holds none is refused as well."""
    contradictory = StageResponseCapture(
        stage="evm_sandbox",
        attempted=True,
        executed=True,
        response_received=True,
        provider_response=None,
        runtime_identity=None,
        runtime_identity_source="",
        response_source="the response of the evm_sandbox stage",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    with pytest.raises(EvidenceContractError):
        build_stage_evidence_artifact(
            contradictory, target_id="T-01", correlation_id="corr-test"
        )


# ===========================================================================
# 2) Finding 2 - the envelope belongs to the captured response
# ===========================================================================

@pytest.mark.parametrize(
    "captured_response",
    ["ok", ["ok"], 42, 3.5, True],
    ids=["string", "list", "int", "float", "bool"],
)
def test_iteration18_a_fabricated_envelope_next_to_a_non_object_response_is_rejected(
    captured_response: Any,
):
    """
    The defect of Finding 2, as a regression test.

    The binding between the envelope and the captured response was checked
    only for a payload that is an object. A payload that is a string, a list
    or a scalar cannot carry an envelope - the artifact must be rejected, not
    passed because the check was skipped.
    """
    envelope = _runtime_identity()
    capture = _capture(
        "evm_sandbox",
        provider_response=captured_response,
        runtime_identity=None,
    )
    payload = _artifact(capture)

    # The mutation: a fabricated envelope next to the captured payload.
    payload["runtime_identity"] = envelope
    payload["runtime_envelope_received"] = True
    payload["runtime_identity_source"] = "modal_runtime"
    payload["absence_records"] = _records_for(payload)
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "can therefore not carry the runtime-identity envelope" in error


def test_iteration18_an_envelope_without_its_source_key_is_rejected():
    """The envelope has to be at the source the artifact names."""
    envelope = _runtime_identity()
    capture = _capture(
        "evm_sandbox",
        provider_response={"verdict": "ok"},
        runtime_identity=None,
    )
    payload = _artifact(capture)

    payload["runtime_identity"] = envelope
    payload["runtime_envelope_received"] = True
    payload["runtime_identity_source"] = "modal_runtime"
    payload["absence_records"] = _records_for(payload)
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "does not contain the runtime-identity envelope at 'modal_runtime'" in error


def test_iteration18_a_different_envelope_at_the_source_is_rejected():
    """The envelope of the artifact must be the one the payload carries."""
    envelope = _runtime_identity()
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
    )
    payload = _artifact(capture)

    # Only the artifact's own envelope is swapped: the captured response still
    # carries the envelope the provider really returned.
    other = _runtime_identity(
        container_id={
            "status": OBSERVED,
            "value": "other-container",
            "source": "MODAL_WORKER_ID of the running container",
        }
    )
    payload["runtime_identity"] = other
    payload["absence_records"] = _records_for(payload)
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "not the one the returned payload carries" in error


def test_iteration18_the_producer_refuses_an_unbound_envelope():
    """The producer may not store an envelope its payload does not carry."""
    envelope = _runtime_identity()
    unbound = StageResponseCapture(
        stage="evm_sandbox",
        attempted=True,
        executed=True,
        response_received=True,
        provider_response={"verdict": "ok"},
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime",
        response_source="the response of the evm_sandbox stage",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    with pytest.raises(EvidenceContractError) as excinfo:
        build_stage_evidence_artifact(unbound, target_id="T-01", correlation_id="corr-test")
    assert "does not contain the runtime-identity envelope" in str(excinfo.value)


def test_iteration18_an_artifact_may_not_name_the_source_of_an_envelope_it_does_not_hold():
    """The source is recorded only when an envelope was received."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"verdict": "ok"},
        runtime_identity=None,
    )
    payload = _artifact(capture)
    payload["runtime_identity_source"] = "modal_runtime"

    ok, error = _validate(payload)
    assert ok is False
    assert "names the source of a runtime-identity envelope it does not hold" in error


# ===========================================================================
# 3) Finding 3 - an identity fact is a typed fact or nothing
# ===========================================================================

MALFORMED_FACTS: List[Tuple[str, Any]] = [
    ("a bare string", "some-id"),
    ("null", None),
    ("a list", ["some-id"]),
    ("an unknown status", {"status": "MAYBE", "value": "x", "source": "src"}),
    ("an observed fact with a null value", {"status": OBSERVED, "value": None, "source": "src"}),
    ("an observed fact with a number", {"status": OBSERVED, "value": 42, "source": "src"}),
    ("an observed fact with an object", {"status": OBSERVED, "value": {"a": 1}, "source": "src"}),
    ("an observed fact without a source", {"status": OBSERVED, "value": "x"}),
    ("an observed fact with an empty value", {"status": OBSERVED, "value": "  ", "source": "src"}),
    (
        "a not-available fact with a value",
        {"status": NOT_AVAILABLE, "value": "x", "reason": "the provider did not expose it"},
    ),
    ("a not-available fact without a reason", {"status": NOT_AVAILABLE, "value": None}),
]


@pytest.mark.parametrize(
    "malformed",
    [fact for _label, fact in MALFORMED_FACTS],
    ids=[label for label, _fact in MALFORMED_FACTS],
)
def test_iteration18_a_malformed_identity_fact_is_rejected(malformed: Any):
    """
    The defect of Finding 3, as a regression test.

    A field that is present but malformed is an error. The artifact is
    rejected - the malformed field is never re-labelled as a field the
    provider omitted.

    The envelope is malformed in the captured response **and** in the
    artifact, so the binding between the two stays intact and only the schema
    of the fact can give the tampering away.
    """
    envelope = _runtime_identity()
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
    )
    payload = _artifact(capture)
    payload = _swap_envelope(payload, _runtime_identity(container_id=malformed))

    ok, error = _validate(payload)
    assert ok is False
    assert "carries a malformed fact for 'container_id'" in error


def test_iteration18_a_malformed_field_is_not_downgraded_to_a_provider_omission():
    """
    The downgrade of Finding 3, as a regression test.

    The classifier would call the malformed field a provider omission - the
    provider "did not report" it. The validator must reject the artifact
    before that downgrade can survive.
    """
    envelope = _runtime_identity()
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
    )
    payload = _artifact(capture)
    malformed = _runtime_identity(container_id="some-id")
    payload = _swap_envelope(payload, malformed)

    # The downgrade that must not happen.
    assert classify_absence_kind(
        attempted=True,
        response_received=True,
        requested_fields=MODAL_IDENTITY_FIELDS,
        runtime_identity=malformed,
        field_name="container_id",
    ) == ABSENCE_PROVIDER_FIELD_OMITTED

    ok, error = _validate(payload)
    assert ok is False
    assert "carries a malformed fact for 'container_id'" in error


def test_iteration18_a_well_formed_fact_is_accepted():
    """The documented representation of a fact is accepted."""
    envelope = _runtime_identity()
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
    )
    payload = _artifact(capture)

    ok, error = _validate(payload)
    assert ok is True, error
    assert validate_runtime_identity_envelope(envelope) == (True, None)


def test_iteration18_a_not_available_fact_is_accepted():
    """A provider that says "not available" is a documented provider omission."""
    envelope = _runtime_identity(
        container_id={
            "status": NOT_AVAILABLE,
            "value": None,
            "reason": "the container exposed neither MODAL_WORKER_ID nor HOSTNAME",
        }
    )
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
    )
    payload = _artifact(capture)
    payload["absence_records"] = _records_for(payload)
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is True, error
    kinds = {record["field"]: record["kind"] for record in payload["absence_records"]}
    assert kinds["container_id"] == ABSENCE_PROVIDER_FIELD_OMITTED
    assert "function_call_id" not in kinds


def test_iteration18_the_producer_refuses_a_malformed_envelope():
    """The producer refuses to write an artifact with a malformed envelope."""
    envelope = _runtime_identity(container_id="some-id")
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
    )
    with pytest.raises(EvidenceContractError) as excinfo:
        build_stage_evidence_artifact(capture, target_id="T-01", correlation_id="corr-test")
    assert "malformed fact for 'container_id'" in str(excinfo.value)


def test_iteration18_the_producer_and_the_validator_agree_about_the_envelope():
    """Whatever the producer accepts, the validator accepts as well."""
    envelope_without_container = _runtime_identity()
    envelope_without_container.pop("container_id")
    envelopes = [
        _runtime_identity(),
        envelope_without_container,
        _runtime_identity(
            container_id={
                "status": NOT_AVAILABLE,
                "value": None,
                "reason": "the container exposed neither MODAL_WORKER_ID nor HOSTNAME",
            }
        ),
    ]
    for envelope in envelopes:
        capture = _capture(
            "evm_sandbox",
            provider_response={"modal_runtime": envelope},
            runtime_identity=envelope,
        )
        payload = build_stage_evidence_artifact(
            capture, target_id="T-01", correlation_id="corr-test"
        )
        ok, error = validate_stage_evidence_artifact(payload, expected_stage="evm_sandbox")
        assert ok is True, error


# ===========================================================================
# 4) The honest cases still pass
# ===========================================================================

def test_iteration18_the_honest_four_stage_case_is_accepted(tmp_path):
    """The four situations of the review stay valid."""
    captures = {
        "inference": _capture(
            "inference",
            attempted=False,
            executed=False,
            response_received=False,
            provider_response=None,
            runtime_identity=None,
        ),
        "evm_sandbox": _capture(
            "evm_sandbox",
            provider_response={"verdict": "ok"},
            runtime_identity=None,
        ),
        "independent_replay": _capture(
            "independent_replay",
            provider_response={"modal_runtime": _runtime_identity()},
            runtime_identity=_runtime_identity(),
        ),
        "trajectory_persistence": _capture(
            "trajectory_persistence",
            provider_response="/vol/models/trajectories/traj_1.json",
            runtime_identity=None,
            requested_fields=(),
        ),
    }

    for stage_name, capture in captures.items():
        path, _ref = write_stage_evidence_artifact(
            tmp_path, capture, target_id="T-01", correlation_id="corr-test"
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        ok, error = validate_stage_evidence_artifact(payload, expected_stage=stage_name)
        assert ok is True, f"{stage_name}: {error}"


def test_iteration18_the_producer_writes_artifacts_the_validator_accepts(tmp_path):
    """Whatever the producer writes is accepted by the strengthened validator."""
    envelope = _runtime_identity()
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
    )
    path, _ref = write_stage_evidence_artifact(
        tmp_path, capture, target_id="T-01", correlation_id="corr-test"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    ok, error = validate_stage_evidence_artifact(payload, expected_stage="evm_sandbox")
    assert ok is True, error


def test_iteration18_every_state_of_the_table_is_accepted():
    """Every state of the Iteration 17 table is still a valid artifact."""
    from benchmarks.evidence_integrity import (
        STAGE_FLAG_NAMES,
        STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE,
        STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE,
        STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
        STAGE_STATE_NOT_ATTEMPTED,
        STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED,
        STAGE_STATE_TABLE,
    )

    states = {
        STAGE_STATE_NOT_ATTEMPTED: (False, False, False, False),
        STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE: (True, False, False, False),
        STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED: (True, False, True, False),
        STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE: (True, True, True, False),
        STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE: (True, True, True, True),
    }
    assert set(states) == set(STAGE_STATE_TABLE.values())
    assert len(STAGE_FLAG_NAMES) == 4

    for state, (attempted, executed, response_received, envelope_received) in states.items():
        envelope = _runtime_identity() if envelope_received else None
        capture = _capture(
            "evm_sandbox",
            attempted=attempted,
            executed=executed,
            response_received=response_received,
            provider_response=(
                {"modal_runtime": envelope} if envelope is not None else {"verdict": "ok"}
            ),
            runtime_identity=envelope,
        )
        payload = _artifact(capture)
        ok, error = _validate(payload)
        assert ok is True, f"{state}: {error}"


def test_iteration18_the_artifact_hashes_the_canonical_json_of_the_payload():
    """The digest describes the canonical serialization of the payload."""
    provider_response = {"modal_runtime": _runtime_identity()}
    capture = _capture(
        "evm_sandbox",
        provider_response=provider_response,
        runtime_identity=_runtime_identity(),
    )
    payload = _artifact(capture)
    metadata = payload["provider_response_metadata"]

    assert metadata["response_sha256"] == sha256_bytes(
        canonical_json_bytes(provider_response)
    )
    assert metadata["response_byte_length"] == len(
        canonical_json_bytes(provider_response)
    )
    # The digest is NOT the digest of a raw transport serialization: it is the
    # digest of the canonical JSON of the returned payload object.
    assert metadata["response_sha256"] != sha256_bytes(
        json.dumps(provider_response).encode("utf-8")
    )


def test_iteration18_the_documentation_keeps_the_canonical_distinction():
    """The docs must not call the canonical serialization transport bytes."""
    matrix = CHANGE_IMPACT_MATRIX.read_text(encoding="utf-8")
    assert "canonical JSON" in matrix
    assert not re.search(r"verbatim transport bytes", matrix, flags=re.IGNORECASE)


# ===========================================================================
# 5) The adapter fails closed on a broken envelope
# ===========================================================================

def test_iteration18_the_adapter_fails_closed_on_a_malformed_envelope(tmp_path):
    """
    A broken envelope must not produce an artifact.

    The adapter turns the refusal of the producer into a failed target with
    an explicit reason: fail closed, never a silent success and never a
    misleading artifact.
    """
    from unittest import mock

    import modal_app
    from benchmarks.adapters import FullAegisRLVRBaselineAdapter
    from benchmarks.protocol import BenchmarkDataset
    from core.schemas import AttackHypothesis, ExploitPayload

    malformed_envelope = {
        "app_id": {
            "status": OBSERVED,
            "value": APP_ID,
            "source": "modal.running_app().app_id",
        },
        # A malformed fact: the container id is a bare string.
        "container_id": "hokkglpxczflmxlcnxxg",
    }

    def mock_verify_exploit_remote(target_dict, payload_dict):
        return {
            "target_name": "Vault",
            "vulnerability_type": "ReentrancyDrain",
            "poc_code": "contract ExploitModule {}",
            "category": "INVARIANT_BREACH_UNREPLAYED",
            "reward_score": 0.5,
            "reward_components": {},
            "is_verified": False,
            "reproducible": False,
            "feedback": "Remote EVM invariant breach achieved",
            "modal_runtime": malformed_envelope,
        }

    def mock_verify_replay_remote(target_dict, payload_dict):
        return {"reproduced": False, "status": "FAILED", "reason": "not reached"}

    def mock_record_trajectory_remote(traj_dict):
        return "/vol/models/trajectories/traj_1.json"

    dataset = BenchmarkDataset()
    vault_target = [
        target for target in dataset.get_public_targets() if target.target_name == "Vault"
    ][0]
    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Trace",
            attack_vector="Drain",
        ),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )

    with mock.patch.object(
        FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None)
    ), mock.patch.object(
        modal_app.verify_exploit_remote, "remote", mock_verify_exploit_remote
    ), mock.patch.object(
        modal_app.verify_replay_remote, "remote", mock_verify_replay_remote
    ), mock.patch.object(
        modal_app.record_trajectory_remote, "remote", mock_record_trajectory_remote
    ):
        adapter = FullAegisRLVRBaselineAdapter(
            candidate_generator=lambda prog: dummy_payload
        )
        artifact = adapter.execute_target(vault_target, replay_artifact_dir=tmp_path)

    assert artifact.status.value == "FAILED"
    assert "fails closed" in (artifact.unavailable_reason or "")
    assert "malformed fact for 'container_id'" in (artifact.unavailable_reason or "")
    assert artifact.tool_metadata.get("error_type") == "EvidenceContractError"
    assert artifact.tool_metadata.get("stage_failed") == "evm_sandbox"


# ===========================================================================
# 6) Validation artifact and CI
# ===========================================================================

def test_iteration18_validation_evidence_is_bound_to_the_code_sha():
    """The published validation evidence must name the code SHA it came from."""
    assert VALIDATION_EVIDENCE.is_file(), "the Iteration 18 validation evidence is missing"
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))

    assert report["generator"] == "benchmarks/validate_iteration18_evidence.py"

    code_sha = report["code_sha"]
    assert isinstance(code_sha, str) and re.fullmatch(r"[0-9a-f]{40}", code_sha), code_sha

    result = subprocess.run(
        ["git", "cat-file", "-t", code_sha],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"{code_sha} is not a commit of this repository"

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


def test_iteration18_validation_evidence_reports_the_binding_per_target():
    """The report must check the response/envelope binding per target."""
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    assert report["per_target"], "the report must carry the per-target results"

    for entry in report["per_target"]:
        check = entry["P0.1.response_envelope_binding"]
        assert check["check"] == "P0.1.response_envelope_binding"
        assert check["status"] in ("PASSED", "FAILED", "NOT_APPLICABLE")
        if check["status"] == "FAILED":
            assert check["error"], "a failed check must say why"


def test_iteration18_validation_evidence_check_mode_detects_a_foreign_code_sha(tmp_path):
    """The --check mode must refuse a report that belongs to another commit."""
    from benchmarks.validate_iteration18_evidence import main

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    report["code_sha"] = "0" * 40
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps(report), encoding="utf-8")

    exit_code = main(["--check", "--report", str(foreign), "--code-sha", "a" * 40])
    assert exit_code == 1


def test_iteration18_ci_workflow_runs_the_new_suite():
    """CI must execute the Iteration 18 suite and the Iteration 18 validator."""
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "tests/test_iteration18_evidence_integrity.py" in ci
    assert "benchmarks.validate_iteration18_evidence" in ci
