"""
tests/test_iteration17_evidence_integrity.py
=============================================

Iteration 17 (PR #12 follow-up) - the stage-evidence state machine.

The Iteration 16 review found a validator bypass in
``benchmarks/evidence_integrity.py``: the ``PROVIDER_FIELD_OMITTED`` branch
checked that a response and a runtime envelope existed and that the field was
not OBSERVED, but it never checked that the client had actually **requested**
the field. An artifact could therefore claim that the provider omitted
``container_id`` for a field the client never asked for - a statement about the
provider that nobody can prove.

The same review found that the flags of an artifact were checked one by one
instead of as a state: ``STAGE_EXECUTED_NO_RUNTIME_ENVELOPE`` did not require
``response_received=True``, so a contradictory "the stage answered, and by the
way it received no response" state could pass.

Iteration 17 therefore:

* defines ONE state table for the four flags of a stage and rejects every
  combination that cannot happen;
* gives every kind of absence the exact states it may describe and the exact
  statement it must make about ``requested_fields``;
* makes the producer and the validator use the same classifier, so a record can
  never claim a kind the state of its own artifact does not allow;
* requires the set of absence records to be complete and unique: every
  identity field the state leaves unavailable has exactly one record, and
  every field the provider reported has none.

Every adversarial test mutates a flag or ``requested_fields`` of an otherwise
valid artifact and keeps the JSON digests internally consistent, so the
validator can only reject it on the state machine itself.
"""

from __future__ import annotations

import itertools
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    ABSENCE_CLIENT_NEVER_CAPTURED_FIELD,
    ABSENCE_KINDS,
    ABSENCE_KINDS_THAT_MAY_CLAIM_PROVIDER_OMISSION,
    ABSENCE_KIND_RULES,
    ABSENCE_PROVIDER_FIELD_OMITTED,
    ABSENCE_REQUESTED_ABSENT,
    ABSENCE_REQUESTED_PRESENT,
    ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE,
    ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE,
    ABSENCE_STAGE_NOT_ATTEMPTED,
    MODAL_IDENTITY_FIELDS,
    NOT_AVAILABLE,
    OBSERVED,
    STAGE_FLAG_NAMES,
    STAGE_STATE_TABLE,
    STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE,
    STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE,
    STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
    STAGE_STATE_NOT_ATTEMPTED,
    STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED,
    StageResponseCapture,
    build_evidence_ref_from_bytes,
    build_stage_evidence_artifact,
    canonical_json_bytes,
    classify_absence_kind,
    sha256_bytes,
    validate_stage_evidence_artifact,
    write_stage_evidence_artifact,
)

VALIDATION_EVIDENCE = _ROOT / "benchmarks" / "evidence" / "iteration17_validation_evidence.json"
CHANGE_IMPACT_MATRIX = (
    _ROOT / "benchmarks" / "evidence" / "iteration17_change_impact_matrix.md"
)

APP_ID = "ap-EDUitOwWeMrIdYbTh4kB63"
FUNCTION_CALL_ID = "fc-8Hq2ZpQrVt3Lb"
CONTAINER_ID = "hokkglpxczflmxlcnxxg"

#: The flags of every state of the state table.
STATE_FLAGS: Dict[str, Tuple[bool, bool, bool, bool]] = {
    STAGE_STATE_NOT_ATTEMPTED: (False, False, False, False),
    STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE: (True, False, False, False),
    STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED: (True, False, True, False),
    STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE: (True, True, True, False),
    STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE: (True, True, True, True),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _runtime_identity(*, omit: Sequence[str] = (), **overrides: Any) -> Dict[str, Any]:
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
    for field_name in omit:
        identity.pop(field_name, None)
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
    """Build the capture of one stage."""
    if provider_response is None and runtime_identity is not None:
        provider_response = {"modal_runtime": runtime_identity}
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
    internally consistent and the validator can only reject it on the state
    machine itself.
    """
    provider_bytes = canonical_json_bytes(payload.get("provider_response"))
    metadata = payload["provider_response_metadata"]
    metadata["response_sha256"] = sha256_bytes(provider_bytes)
    metadata["response_byte_length"] = len(provider_bytes)
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


def _artifact(
    capture: StageResponseCapture,
    *,
    flags: Optional[Tuple[bool, bool, bool, bool]] = None,
    requested_fields: Optional[Sequence[str]] = None,
    runtime_identity: Any = "__keep__",
    absence_records: Any = "__keep__",
    stage: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build an artifact of one stage, optionally mutated.

    The mutation keeps the artifact internally consistent: the flags, the
    requested fields, the envelope and the absence records are replaced
    together and every digest is recomputed afterwards.
    """
    payload = build_stage_evidence_artifact(
        capture, target_id="T-01", correlation_id="corr-test"
    )

    if flags is not None:
        attempted, executed, response_received, envelope_received = flags
        payload["attempted"] = attempted
        payload["executed"] = executed
        payload["response_received"] = response_received
        payload["runtime_envelope_received"] = envelope_received

    if requested_fields is not None:
        payload["requested_fields"] = list(requested_fields)

    if runtime_identity != "__keep__":
        payload["runtime_identity"] = runtime_identity
        payload["runtime_envelope_received"] = runtime_identity is not None
        payload["runtime_identity_source"] = "modal_runtime" if runtime_identity is not None else ""
        if isinstance(runtime_identity, dict) and isinstance(payload.get("provider_response"), dict):
            payload["provider_response"]["modal_runtime"] = runtime_identity

    if absence_records != "__keep__":
        payload["absence_records"] = absence_records
    else:
        payload["absence_records"] = _records_for(payload)

    if stage is not None:
        payload["stage"] = stage

    return _recompute_digests(payload)


def _validate(payload: Dict[str, Any], stage: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Validate an artifact against the stage it declares."""
    return validate_stage_evidence_artifact(
        payload, expected_stage=stage or payload.get("stage", "evm_sandbox")
    )


# ===========================================================================
# 1) The state table itself
# ===========================================================================

def test_iteration17_state_table_covers_every_state_of_a_stage():
    """The table names every state a stage can be in - and only those."""
    assert set(STATE_FLAGS) == set(STAGE_STATE_TABLE.values())
    assert len(STAGE_STATE_TABLE) == 5
    for state, flags in STATE_FLAGS.items():
        assert STAGE_STATE_TABLE[flags] == state


def test_iteration17_state_table_rejects_every_impossible_combination():
    """No other combination of the four flags is a state of a stage."""
    all_combinations = list(itertools.product((False, True), repeat=len(STAGE_FLAG_NAMES)))
    impossible = [
        combination
        for combination in all_combinations
        if combination not in STAGE_STATE_TABLE
    ]
    # 16 combinations, 5 of them are states.
    assert len(impossible) == 11


@pytest.mark.parametrize(
    "flags",
    [
        # not attempted + executed / response / envelope
        (False, True, False, False),
        (False, False, True, False),
        (False, False, False, True),
        (False, True, True, True),
        # executed without a response
        (True, True, False, False),
        # a response without the stage having been attempted
        (False, False, True, True),
        # an envelope without a response
        (True, False, True, True),
        (True, True, False, True),
        # executed without a response and without an envelope
        (True, False, False, True),
        # executed but not attempted
        (False, True, True, False),
        (False, True, False, True),
    ],
)
def test_iteration17_impossible_flag_combinations_are_rejected(flags):
    """A state that cannot exist is rejected before any record is looked at."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"verdict": "ok"},
        runtime_identity=None,
    )
    payload = _artifact(capture, flags=flags)

    ok, error = _validate(payload)
    assert ok is False
    assert "impossible state" in error


def test_iteration17_every_state_of_the_table_is_accepted():
    """The five states of the table are the five legal shapes of an artifact."""
    for state, flags in STATE_FLAGS.items():
        attempted, executed, response_received, envelope_received = flags
        envelope = _runtime_identity() if envelope_received else None
        capture = _capture(
            "evm_sandbox",
            attempted=attempted,
            executed=executed,
            response_received=response_received,
            provider_response={"modal_runtime": envelope} if envelope else {"verdict": "ok"},
            runtime_identity=envelope,
            runtime_identity_source="modal_runtime" if envelope else "",
        )
        payload = _artifact(capture, flags=flags)
        ok, error = _validate(payload)
        assert ok is True, f"{state}: {error}"


def test_iteration17_producer_and_validator_share_one_classifier():
    """The kind the producer writes is the kind the validator derives."""
    for state, flags in STATE_FLAGS.items():
        attempted, executed, response_received, envelope_received = flags
        envelope = _runtime_identity() if envelope_received else None
        capture = _capture(
            "evm_sandbox",
            attempted=attempted,
            executed=executed,
            response_received=response_received,
            provider_response={"modal_runtime": envelope} if envelope else {"verdict": "ok"},
            runtime_identity=envelope,
            runtime_identity_source="modal_runtime" if envelope else "",
        )
        payload = _artifact(capture, flags=flags)
        for record in payload["absence_records"]:
            derived = classify_absence_kind(
                attempted=payload["attempted"],
                response_received=payload["response_received"],
                requested_fields=payload["requested_fields"],
                runtime_identity=payload.get("runtime_identity"),
                field_name=record["field"],
            )
            assert record["kind"] == derived
            assert payload["attempted"] or True  # the flags are what they are
            assert derived in ABSENCE_KINDS


# ===========================================================================
# 2) The bypass of the Iteration 16 review
# ===========================================================================

def test_iteration17_provider_omission_for_an_unrequested_field_is_rejected():
    """
    The exact bypass of the Iteration 16 review, as a regression test.

    The client asked the provider for the application id and the function-call
    id, but never for the container id. The artifact claims that the provider
    omitted the container id - a statement about the provider that nobody can
    prove, because the provider was never asked.
    """
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity(omit=("container_id",))},
        runtime_identity=_runtime_identity(omit=("container_id",)),
        requested_fields=("app_id", "function_call_id"),
    )
    payload = _artifact(capture)

    # The honest kind of the container id in this state.
    assert payload["absence_records"] == [
        {
            "kind": ABSENCE_CLIENT_NEVER_CAPTURED_FIELD,
            "field": "container_id",
            "reason": payload["absence_records"][0]["reason"],
        }
    ]

    # The bypass: the artifact blames the provider for a field the client
    # never requested. The digests stay consistent - only the kind changes.
    payload["absence_records"][0]["kind"] = ABSENCE_PROVIDER_FIELD_OMITTED
    payload["absence_records"][0]["reason"] = (
        "the provider's response for the evm_sandbox stage does not contain 'container_id'"
    )
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "never requested that field" in error


def test_iteration17_provider_omission_may_be_claimed_for_a_requested_field():
    """The honest provider omission - a requested field the envelope omits."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity(omit=("container_id",))},
        runtime_identity=_runtime_identity(omit=("container_id",)),
    )
    payload = _artifact(capture)

    kinds = {record["field"]: record["kind"] for record in payload["absence_records"]}
    assert kinds == {"container_id": ABSENCE_PROVIDER_FIELD_OMITTED}

    ok, error = _validate(payload)
    assert ok is True, error


def test_iteration17_provider_omission_needs_the_field_in_requested_fields():
    """The same bypass, this time by emptying ``requested_fields``."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity()},
        runtime_identity=_runtime_identity(),
    )
    payload = _artifact(capture)

    # The provider omitted nothing here: the envelope reports every field.
    payload["absence_records"] = [
        {
            "kind": ABSENCE_PROVIDER_FIELD_OMITTED,
            "field": "container_id",
            "reason": "the provider's response does not contain 'container_id'",
        }
    ]
    payload["requested_fields"] = ["app_id", "function_call_id"]
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "never requested that field" in error


def test_iteration17_provider_omission_requires_a_response_and_an_envelope():
    """A provider omission needs the response and the envelope to exist."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity(omit=("container_id",))},
        runtime_identity=_runtime_identity(omit=("container_id",)),
    )
    payload = _artifact(capture)

    # The envelope is gone: the artifact cannot claim that the provider
    # omitted a field of an envelope it does not hold.
    payload["runtime_identity"] = None
    payload["runtime_envelope_received"] = False
    payload["runtime_identity_source"] = ""
    payload["provider_response"].pop("modal_runtime", None)
    payload["absence_records"] = [
        {
            "kind": ABSENCE_PROVIDER_FIELD_OMITTED,
            "field": "container_id",
            "reason": "the provider's response does not contain 'container_id'",
        }
    ]
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    # A provider omission is only possible in the state in which the stage
    # received a runtime-identity envelope.
    assert "although the state of the stage is" in error
    assert STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE not in ABSENCE_KIND_RULES[
        ABSENCE_PROVIDER_FIELD_OMITTED
    ]["states"]


def test_iteration17_an_artifact_that_claims_an_envelope_must_hold_one():
    """The flag ``runtime_envelope_received`` needs the envelope itself."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity(omit=("container_id",))},
        runtime_identity=_runtime_identity(omit=("container_id",)),
    )
    payload = _artifact(capture)
    payload["runtime_identity"] = None
    payload["runtime_envelope_received"] = True
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "claims a runtime-identity envelope but holds none" in error


def test_iteration17_provider_omission_must_be_genuinely_absent():
    """A field the envelope reports cannot be claimed to be omitted."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity()},
        runtime_identity=_runtime_identity(),
    )
    payload = _artifact(capture)
    payload["absence_records"] = [
        {
            "kind": ABSENCE_PROVIDER_FIELD_OMITTED,
            "field": "container_id",
            "reason": "the provider's response does not contain 'container_id'",
        }
    ]
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "although the provider reported it" in error


def test_iteration17_provider_omission_may_not_be_claimed_without_a_response():
    """The failed-attempt state cannot carry a provider omission."""
    capture = _capture(
        "evm_sandbox",
        attempted=True,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    payload = _artifact(capture)
    payload["absence_records"] = [
        {
            "kind": ABSENCE_PROVIDER_FIELD_OMITTED,
            "field": "container_id",
            "reason": "the provider's response does not contain 'container_id'",
        }
    ]
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "although the state of the stage is" in error


# ===========================================================================
# 3) The state decides which kinds of absence are possible
# ===========================================================================

def test_iteration17_kind_rules_match_what_can_really_happen():
    """
    Every rule of the table matches the situations that can occur.

    For every state the possible setups are enumerated - which fields the
    client requested and what the envelope contains - and the kinds that the
    shared classifier can produce are compared with the states the rule table
    allows.
    """
    for state in STATE_FLAGS:
        attempted, _executed, response_received, envelope_received = STATE_FLAGS[state]
        # The envelope has to be consistent with the state: a stage that
        # received no envelope has no envelope.
        envelopes: Iterable[Optional[Dict[str, Any]]]
        if envelope_received:
            envelopes = (_runtime_identity(), _runtime_identity(omit=("container_id",)))
        else:
            envelopes = (None,)
        for requested_fields in ((), ("container_id",), MODAL_IDENTITY_FIELDS):
            for envelope in envelopes:
                possible = set()
                for field_name in MODAL_IDENTITY_FIELDS:
                    kind = classify_absence_kind(
                        attempted=attempted,
                        response_received=response_received,
                        requested_fields=requested_fields,
                        runtime_identity=envelope,
                        field_name=field_name,
                    )
                    if kind is not None:
                        possible.add(kind)
                for kind in possible:
                    assert state in ABSENCE_KIND_RULES[kind]["states"], (
                        f"{state} can produce {kind}, but the rule table does not allow it"
                    )


@pytest.mark.parametrize(
    "state,kind,allowed",
    [
        (STAGE_STATE_NOT_ATTEMPTED, ABSENCE_STAGE_NOT_ATTEMPTED, True),
        (STAGE_STATE_NOT_ATTEMPTED, ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE, False),
        (STAGE_STATE_NOT_ATTEMPTED, ABSENCE_CLIENT_NEVER_CAPTURED_FIELD, False),
        (STAGE_STATE_NOT_ATTEMPTED, ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE, False),
        (STAGE_STATE_NOT_ATTEMPTED, ABSENCE_PROVIDER_FIELD_OMITTED, False),
        (
            STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE,
            ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE,
            True,
        ),
        (STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE, ABSENCE_STAGE_NOT_ATTEMPTED, False),
        (STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE, ABSENCE_CLIENT_NEVER_CAPTURED_FIELD, False),
        (
            STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE,
            ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE,
            False,
        ),
        (STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE, ABSENCE_PROVIDER_FIELD_OMITTED, False),
        (
            STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED,
            ABSENCE_CLIENT_NEVER_CAPTURED_FIELD,
            True,
        ),
        (
            STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED,
            ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE,
            True,
        ),
        (STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED, ABSENCE_PROVIDER_FIELD_OMITTED, False),
        (STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED, ABSENCE_STAGE_NOT_ATTEMPTED, False),
        (
            STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED,
            ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE,
            False,
        ),
        (
            STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE,
            ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE,
            True,
        ),
        (
            STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE,
            ABSENCE_CLIENT_NEVER_CAPTURED_FIELD,
            True,
        ),
        (STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE, ABSENCE_PROVIDER_FIELD_OMITTED, False),
        (STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE, ABSENCE_STAGE_NOT_ATTEMPTED, False),
        (
            STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE,
            ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE,
            False,
        ),
        (
            STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
            ABSENCE_PROVIDER_FIELD_OMITTED,
            True,
        ),
        (
            STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
            ABSENCE_CLIENT_NEVER_CAPTURED_FIELD,
            True,
        ),
        (
            STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
            ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE,
            False,
        ),
        (STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE, ABSENCE_STAGE_NOT_ATTEMPTED, False),
        (
            STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
            ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE,
            False,
        ),
    ],
)
def test_iteration17_a_kind_may_only_be_claimed_in_the_states_that_allow_it(
    state: str, kind: str, allowed: bool
):
    """Claiming a kind in a state that does not allow it is rejected."""
    attempted, executed, response_received, envelope_received = STATE_FLAGS[state]
    envelope = _runtime_identity(omit=("container_id",)) if envelope_received else None
    capture = _capture(
        "evm_sandbox",
        attempted=attempted,
        executed=executed,
        response_received=response_received,
        provider_response={"modal_runtime": envelope} if envelope else {"verdict": "ok"},
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime" if envelope else "",
    )
    payload = _artifact(capture, flags=STATE_FLAGS[state])
    payload["absence_records"] = [
        {
            "kind": kind,
            "field": "container_id",
            "reason": "the state of the stage makes this field unavailable",
        }
    ]
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    if allowed:
        # The kind itself is possible in this state: the artifact may still be
        # rejected because the record does not match the state of the field -
        # but never because of the state of the stage.
        assert "although the state of the stage is" not in (error or "")
    else:
        assert ok is False
        assert "although the state of the stage is" in error


def test_iteration17_client_never_captured_requires_an_unrequested_field():
    """A field the client asked for cannot be claimed as never requested."""
    capture = _capture(
        "trajectory_persistence",
        provider_response="/vol/models/trajectories/traj_1.json",
        runtime_identity=None,
        runtime_identity_source="",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    payload = _artifact(capture)
    payload["absence_records"] = [
        {
            "kind": ABSENCE_CLIENT_NEVER_CAPTURED_FIELD,
            "field": "container_id",
            "reason": "this client never requested 'container_id' from the stage",
        }
    ]
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "the client asked for it" in error


def test_iteration17_executed_without_envelope_requires_a_response():
    """
    The defect the Iteration 16 review named.

    ``STAGE_EXECUTED_NO_RUNTIME_ENVELOPE`` used to be accepted with
    ``response_received=False`` - a stage that answered and, at the same time,
    received no response.
    """
    capture = _capture(
        "evm_sandbox",
        provider_response={"verdict": "ok"},
        runtime_identity=None,
    )
    payload = _artifact(capture)
    payload["absence_records"] = [
        {
            "kind": ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE,
            "field": "container_id",
            "reason": "the stage returned a response that carried no runtime-identity envelope",
        }
    ]
    # The contradictory state: the stage answered and received no response.
    payload["response_received"] = False
    payload["provider_response"] = None
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "impossible state" in error


def test_iteration17_failed_attempt_may_not_claim_a_response():
    """A failed attempt cannot be recorded next to a received response."""
    capture = _capture(
        "independent_replay",
        attempted=True,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    payload = _artifact(capture)
    payload["absence_records"] = [
        {
            "kind": ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE,
            "field": "container_id",
            "reason": "the stage was attempted but returned no response",
        }
    ]
    payload["response_received"] = True
    payload["provider_response"] = {"verdict": "ok"}
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "although the state of the stage is" in error

    # The failed attempt is the state in which no response came back at all.
    assert STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE in ABSENCE_KIND_RULES[
        ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE
    ]["states"]
    assert STATE_FLAGS[STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE][2] is False


def test_iteration17_not_attempted_may_not_execute():
    """A stage that was never invoked cannot have executed."""
    capture = _capture(
        "independent_replay",
        attempted=False,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    payload = _artifact(capture)
    payload["absence_records"] = [
        {
            "kind": ABSENCE_STAGE_NOT_ATTEMPTED,
            "field": "container_id",
            "reason": "the stage was not attempted for this target",
        }
    ]
    payload["executed"] = True
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "impossible state" in error


# ===========================================================================
# 4) The absence records must be complete and unique
# ===========================================================================

def test_iteration17_a_missing_absence_record_is_rejected():
    """A field the state leaves unavailable must be accounted for."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity(omit=("container_id",))},
        runtime_identity=_runtime_identity(omit=("container_id",)),
    )
    payload = _artifact(capture)
    payload["absence_records"] = [
        record for record in payload["absence_records"] if record["field"] != "container_id"
    ]
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "holds no absence record for 'container_id'" in error


def test_iteration17_a_duplicate_absence_record_is_rejected():
    """The same field may not be accounted for twice."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity(omit=("container_id",))},
        runtime_identity=_runtime_identity(omit=("container_id",)),
    )
    payload = _artifact(capture)
    duplicate = dict(payload["absence_records"][0])
    payload["absence_records"].append(duplicate)
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "absence records for 'container_id'" in error


def test_iteration17_an_absence_record_for_an_observed_field_is_rejected():
    """A field the provider reported cannot also be recorded as absent."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity()},
        runtime_identity=_runtime_identity(),
    )
    payload = _artifact(capture)
    payload["absence_records"] = [
        {
            "kind": ABSENCE_PROVIDER_FIELD_OMITTED,
            "field": "container_id",
            "reason": "the provider's response does not contain 'container_id'",
        }
    ]
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "although the provider reported it" in error


def test_iteration17_the_recorded_kind_must_match_the_state():
    """A record that names another kind than the state allows is rejected."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"verdict": "ok"},
        runtime_identity=None,
    )
    payload = _artifact(capture)
    assert payload["absence_records"][0]["kind"] == ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE
    payload["absence_records"][0]["kind"] = ABSENCE_CLIENT_NEVER_CAPTURED_FIELD
    payload["absence_records"][0]["reason"] = "this client never requested the field"
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "the client asked for it" in error


# ===========================================================================
# 5) The honest cases still pass
# ===========================================================================

def test_iteration17_the_honest_four_stage_case_is_accepted(tmp_path):
    """The four situations of the Iteration 16 review stay valid."""
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
            runtime_identity_source="",
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


def test_iteration17_the_producer_writes_artifacts_the_validator_accepts(tmp_path):
    """Whatever the producer writes is accepted by the strengthened validator."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity(omit=("container_id",))},
        runtime_identity=_runtime_identity(omit=("container_id",)),
    )
    path, _ref = write_stage_evidence_artifact(
        tmp_path, capture, target_id="T-01", correlation_id="corr-test"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    ok, error = validate_stage_evidence_artifact(payload, expected_stage="evm_sandbox")
    assert ok is True, error


def test_iteration17_only_a_provider_omission_may_blame_the_provider():
    """The wording rule of Iteration 16 still holds."""
    capture = _capture(
        "independent_replay",
        attempted=False,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    payload = _artifact(capture)
    payload["absence_records"][0]["reason"] = "the provider did not report the application id"
    payload = _recompute_digests(payload)

    ok, error = _validate(payload)
    assert ok is False
    assert "the provider was never asked" in error

    assert ABSENCE_KINDS_THAT_MAY_CLAIM_PROVIDER_OMISSION == (ABSENCE_PROVIDER_FIELD_OMITTED,)
    for kind in ABSENCE_KINDS:
        assert kind in ABSENCE_KIND_RULES


# ===========================================================================
# 6) The evidence wording: canonical JSON, not transport bytes
# ===========================================================================

def test_iteration17_the_artifact_hashes_the_canonical_json_of_the_payload():
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


def test_iteration17_the_documentation_keeps_the_canonical_distinction():
    """The docs must not call the canonical serialization transport bytes."""
    matrix = CHANGE_IMPACT_MATRIX.read_text(encoding="utf-8")
    assert "canonical JSON" in matrix
    assert not re.search(r"verbatim transport bytes", matrix, flags=re.IGNORECASE)


# ===========================================================================
# 7) Validation artifact and CI
# ===========================================================================

def test_iteration17_validation_evidence_is_bound_to_the_code_sha():
    """The published validation evidence must name the code SHA it came from."""
    assert VALIDATION_EVIDENCE.is_file(), "the Iteration 17 validation evidence is missing"
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))

    assert report["generator"] == "benchmarks/validate_iteration17_evidence.py"

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


def test_iteration17_validation_evidence_reports_the_state_machine_per_target():
    """The report must check the stage state machine per target."""
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    assert report["per_target"], "the report must carry the per-target results"

    for entry in report["per_target"]:
        check = entry["P0.1.stage_state_machine"]
        assert check["check"] == "P0.1.stage_state_machine"
        assert check["status"] in ("PASSED", "FAILED", "NOT_APPLICABLE")
        if check["status"] == "FAILED":
            assert check["error"], "a failed check must say why"


def test_iteration17_validation_evidence_check_mode_detects_a_foreign_code_sha(tmp_path):
    """The --check mode must refuse a report that belongs to another commit."""
    from benchmarks.validate_iteration17_evidence import main

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    report["code_sha"] = "0" * 40
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps(report), encoding="utf-8")

    exit_code = main(["--check", "--report", str(foreign), "--code-sha", "a" * 40])
    assert exit_code == 1


def test_iteration17_ci_workflow_runs_the_new_suite():
    """CI must execute the Iteration 17 suite and the Iteration 17 validator."""
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "tests/test_iteration17_evidence_integrity.py" in ci
    assert "benchmarks.validate_iteration17_evidence" in ci
