"""
benchmarks/evidence_integrity.py
================================

Iteration 14 evidence-integrity primitives (Issue #11).

This module is the single place where the benchmark evidence chain learns to
tell the truth about what it actually observed. Four P0 defect groups are
addressed here, each with one producer-side helper and one consumer-side
validator:

P0.1  Modal provenance and billing attribution
      - provider-issued identifiers are captured from the real Modal runtime,
        never hardcoded;
      - missing provider fields are recorded as an explicit ``NOT_AVAILABLE``
        fact with a reason and a pointer to an immutable evidence artifact
        (path + SHA-256) instead of a synthetic URI;
      - billing is split into app/session level and target level, every raw
        line item is accounted for exactly once, and target-level cost stays
        ``None`` until an invocation-level join is actually proven.

P0.2  Replay integrity envelope
      - no fallback of any kind: no reuse of the initial run's stdout/stderr
        hashes, no reuse of the initial run's timestamps, no synthetic
        container identity;
      - replay stdout/stderr are stored as their own artifacts with byte
        length and SHA-256, and the validator recomputes the digest from the
        stored bytes;
      - candidate and harness digests are checked against the exact replay
        input artifacts.

P0.3  Remote EVM provenance
      - the worker reports the OS details, the immutable image digest, the
        exact Foundry/Solc versions, the exact argv, the working directory and
        the effective compiler settings it actually observed;
      - facts that could not be observed are ``NOT_AVAILABLE`` with a reason;
      - provenance is stored per target/per execution and is never copied onto
        a target whose EVM stage did not run.

P0.4  Safe-control sentinel
      - only the exact documented sentinel of the repository-owned harness is
        accepted, and only for the matching target/harness context;
      - arbitrary prefixes, suffixes, near-matches, generic reverts, panics,
        compilation errors, malformed output and infrastructure failures are
        rejected.

The design rule for the whole module: a fact is either OBSERVED (with the
bytes or value it came from) or NOT_AVAILABLE (with the reason why it could
not be observed). There is no third state, and in particular there is no
state in which a constant, a fallback or a template is presented as if it had
been observed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

#: Marker used for a provider field that the runtime did not expose.
NOT_AVAILABLE = "NOT_AVAILABLE"

#: Marker for a value that could not be observed.
OBSERVED = "OBSERVED"

#: A SHA-256 digest is always exactly 64 lowercase hex characters.
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

#: A Modal application id looks like ``ap-<base62>``.
MODAL_APP_ID_RE = re.compile(r"^ap-[A-Za-z0-9]{8,}$")

#: A Modal function-call id looks like ``fc-<base62>``.
MODAL_FUNCTION_CALL_ID_RE = re.compile(r"^fc-[A-Za-z0-9]{8,}$")

#: A Modal container/worker id is a UUID-like hex token.
MODAL_CONTAINER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,}$")

#: The **provider's** shape of a container id (Iteration 21).
#:
#: The Modal SDK's own command line documents the container id as ``ta-*``
#: (``modal/cli/app.py``: *"Filter by Container ID (ta-*)"*), and the SDK's
#: ``modal container list`` prints the provider's ``TaskStats.task_id`` under
#: the column heading *"Container ID"* (``modal/cli/container.py``). The
#: provider's task id **is** the container id - the SDK's own
#: ``modal/runner.py`` calls the very same field ``get_old_container_ids()``.
#:
#: The loose ``MODAL_CONTAINER_ID_RE`` above stays the shape of the artifacts
#: of Iterations 14-20; this is the strict shape a **provider-issued** value
#: has to have in the strict source mode.
MODAL_PROVIDER_CONTAINER_ID_RE = re.compile(r"^ta-[A-Za-z0-9]{8,}$")

#: Immutable Modal image ids look like ``im-<base62>``.
MODAL_IMAGE_ID_RE = re.compile(r"^im-[A-Za-z0-9]{8,}$")

#: Synthetic container identities that must never be accepted as evidence.
FORBIDDEN_SYNTHETIC_CONTAINER_IDS = frozenset({
    "modal-cpu-replayed",
    "modal-cpu",
    "ephemeral",
    "unknown",
    "container",
    "fresh-container",
})

#: Shape of the synthetic fallback the old client code generated:
#: ``modal-cpu-<12 hex chars of a random uuid>``. It is not a provider-issued
#: identity even though it looks like one.
SYNTHETIC_CONTAINER_ID_RE = re.compile(r"^modal-(cpu|gpu|t4|h100)-[0-9a-f]{12}$")

# ---------------------------------------------------------------------------
# The side of an observation (Iteration 20)
# ---------------------------------------------------------------------------
#
# Modal SDK 1.5.5 gives a function container neither a running-app accessor
# (``modal.running_app`` is a module, not a callable) nor a worker/hostname
# environment variable. A worker can therefore attest the function-call id
# only; the application id and the app page URL of a run are facts of the
# **client**, which reads them from the provider.
#
# A fact that does not name its side stays valid - every artifact of
# Iterations 14-19 has no such name. But a fact that *does* name a side must
# name it correctly: a client observation can never be presented as a worker
# observation.

#: A fact that was observed inside the running worker container.
OBSERVATION_SIDE_WORKER = "worker"

#: A fact that the client observed from the provider.
OBSERVATION_SIDE_CLIENT = "client"

#: Every side an observation may name.
OBSERVATION_SIDES = (OBSERVATION_SIDE_WORKER, OBSERVATION_SIDE_CLIENT)

#: A source that names the client side of an observation.
CLIENT_SIDE_SOURCE_RE = re.compile(r"(?i)\bclient[- ]side\b")

#: A source that names the worker side of an observation.
WORKER_SIDE_SOURCE_RE = re.compile(
    r"(?i)\b(?:worker[- ]side|(?:inside|in|of) the (?:running )?container)\b"
)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    """SHA-256 over the exact bytes given (no encoding, no normalisation)."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """SHA-256 over the UTF-8 encoding of ``text``."""
    return sha256_bytes(text.encode("utf-8"))


def is_sha256(value: Any) -> bool:
    """True only for a well-formed lowercase SHA-256 hex digest."""
    return isinstance(value, str) and bool(SHA256_RE.fullmatch(value))


def file_sha256(path: os.PathLike | str) -> Optional[str]:
    """SHA-256 of a file's exact bytes, or ``None`` when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            return sha256_bytes(handle.read())
    except OSError:
        return None


def is_not_available(value: Any) -> bool:
    """True when a recorded fact is the explicit NOT_AVAILABLE marker."""
    return value == NOT_AVAILABLE


def not_available(
    reason: str,
    *,
    evidence_ref: Optional[Dict[str, Any]] = None,
    absence_kind: Optional[str] = None,
    observed_by: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build an explicit "not available" fact.

    The fact never pretends to hold data. It states the exact reason and, when
    the caller can point at an existing immutable evidence artifact, the
    artifact's path together with its SHA-256 so the claim stays checkable.

    ``absence_kind`` names *why* the fact is missing (Iteration 16). It is
    mandatory for every fact that is produced by the stage-evidence layer,
    because "the provider did not report it" and "this client never asked for
    it" are very different statements.

    ``observed_by`` names the side of the invocation that made the observation
    (Iteration 20). A fact of a worker is worker-side; a fact the client read
    from the provider is client-side. The name is optional so that every
    artifact of Iterations 14-19 stays valid.
    """
    if not reason or not str(reason).strip():
        raise ValueError("A NOT_AVAILABLE fact requires an explicit reason")
    fact: Dict[str, Any] = {
        "status": NOT_AVAILABLE,
        "value": None,
        "reason": str(reason).strip(),
    }
    if absence_kind:
        if absence_kind not in ABSENCE_KINDS:
            raise ValueError(f"Unknown absence kind: {absence_kind!r}")
        fact["absence_kind"] = absence_kind
    if observed_by is not None:
        fact["observed_by"] = _validated_observation_side(observed_by)
    if evidence_ref:
        fact["evidence_ref"] = (
            evidence_ref.to_dict() if hasattr(evidence_ref, "to_dict") else dict(evidence_ref)
        )
    return fact


def observed(value: Any, *, source: str, observed_by: Optional[str] = None) -> Dict[str, Any]:
    """
    Build an observed fact together with the source it was read from.

    ``observed_by`` names the side of the invocation that observed the value
    (Iteration 20): ``"worker"`` for a value read inside the container,
    ``"client"`` for a value the client read from the provider. The name is
    optional so that every artifact of Iterations 14-19 stays valid.
    """
    if not source or not str(source).strip():
        raise ValueError("An OBSERVED fact requires an explicit source")
    fact: Dict[str, Any] = {
        "status": OBSERVED,
        "value": value,
        "source": str(source).strip(),
    }
    if observed_by is not None:
        fact["observed_by"] = _validated_observation_side(observed_by)
    return fact


def _validated_observation_side(observed_by: Any) -> str:
    """Return the side of an observation, or refuse an unknown one."""
    if observed_by not in OBSERVATION_SIDES:
        raise ValueError(
            "An observation side must be one of {sides}, not {value!r}".format(
                sides=", ".join(OBSERVATION_SIDES), value=observed_by
            )
        )
    return str(observed_by)


def attach_evidence_ref(fact: Any, evidence_ref: Any) -> Any:
    """
    Attach an evidence reference to a fact.

    The reference is added to a copy of the fact; the original fact is left
    untouched so that a shared fact object cannot be mutated by accident.
    """
    if not isinstance(fact, dict):
        return fact
    if evidence_ref is None:
        return fact
    updated = dict(fact)
    updated["evidence_ref"] = (
        evidence_ref.to_dict() if hasattr(evidence_ref, "to_dict") else dict(evidence_ref)
    )
    return updated


def build_evidence_ref_from_bytes(
    path: str,
    data: bytes,
    *,
    description: str = "",
) -> Dict[str, Any]:
    """
    Describe bytes that were written to ``path``.

    The digest always describes the exact bytes that were written, so the
    reference can be re-verified against the file on disk.
    """
    return {
        "path": path,
        "sha256": sha256_bytes(data),
        "byte_length": len(data),
        "description": description,
    }


def attach_evidence_ref_to_facts(payload: Any, evidence_ref: Any) -> Any:
    """
    Attach an evidence reference to every ``NOT_AVAILABLE`` fact in a payload.

    The payload is copied, never mutated in place. Facts that already carry
    their own evidence reference keep it: a worker-side reference always
    describes the bytes that back exactly that statement.
    """
    if isinstance(payload, dict):
        updated: Dict[str, Any] = {}
        for key, value in payload.items():
            if (
                isinstance(value, dict)
                and value.get("status") == NOT_AVAILABLE
                and not value.get("evidence_ref")
            ):
                value = attach_evidence_ref(value, evidence_ref)
            updated[key] = attach_evidence_ref_to_facts(value, evidence_ref)
        return updated
    if isinstance(payload, list):
        return [attach_evidence_ref_to_facts(item, evidence_ref) for item in payload]
    if isinstance(payload, tuple):
        return tuple(attach_evidence_ref_to_facts(item, evidence_ref) for item in payload)
    return payload


def fact_value(fact: Any) -> Any:
    """Return the observed value of a fact, or ``None`` when unavailable."""
    if isinstance(fact, dict):
        if fact.get("status") == OBSERVED:
            return fact.get("value")
        return None
    return fact


def fact_is_observed(fact: Any) -> bool:
    """True only when the fact carries an actually observed value."""
    if isinstance(fact, dict):
        return fact.get("status") == OBSERVED and fact.get("value") is not None
    return fact is not None


# ---------------------------------------------------------------------------
# Independently verifiable evidence references (Iteration 15)
# ---------------------------------------------------------------------------

def resolve_evidence_path(
    relative_path: str,
    *,
    evidence_root: os.PathLike | str,
) -> Optional[Path]:
    """
    Resolve an evidence reference path inside the evidence root.

    The path must stay inside the root: an absolute path or a path that
    escapes the root via ``..`` is rejected. ``None`` is returned when the
    reference cannot be resolved safely.
    """
    if not relative_path or not isinstance(relative_path, str):
        return None
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None
    root = Path(evidence_root).resolve()
    try:
        resolved = (root / candidate).resolve()
        resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    return resolved


def validate_evidence_ref_bytes(
    evidence_ref: Any,
    *,
    evidence_root: os.PathLike | str,
) -> Tuple[bool, Optional[str]]:
    """
    Verify that an evidence reference really points at the bytes it claims.

    The reference must name a path and a well-formed SHA-256 digest, the path
    must resolve inside the evidence root, the artifact must exist, and the
    digest of the stored bytes must equal the declared digest.

    A reference to a tampered, missing or malformed artifact is rejected: the
    claim is only verifiable when the bytes confirm it.
    """
    if not isinstance(evidence_ref, dict) or not evidence_ref:
        return False, "Evidence reference is missing or empty"

    path = evidence_ref.get("path")
    digest = evidence_ref.get("sha256")

    if not isinstance(path, str) or not path.strip():
        return False, "Evidence reference has no path"
    if not is_sha256(digest):
        return False, f"Evidence reference has no valid SHA-256 digest: {digest!r}"

    resolved = resolve_evidence_path(path, evidence_root=evidence_root)
    if resolved is None:
        return False, (
            f"Evidence reference path {path!r} is not a relative path inside the evidence root"
        )
    if not resolved.is_file():
        return False, f"Evidence reference points at a missing artifact: {path}"

    data = resolved.read_bytes()
    actual = sha256_bytes(data)
    if actual != digest:
        return False, (
            f"Evidence reference digest {digest} does not match the digest of the referenced "
            f"bytes ({actual})"
        )

    declared_length = evidence_ref.get("byte_length")
    if declared_length is not None:
        if not isinstance(declared_length, int) or isinstance(declared_length, bool):
            return False, "Evidence reference has no valid byte length"
        if declared_length != len(data):
            return False, (
                f"Evidence reference byte length {declared_length} does not match the referenced "
                f"bytes ({len(data)})"
            )

    return True, None


def require_verified_evidence_ref(
    fact: Any,
    *,
    evidence_root: os.PathLike | str,
    label: str,
) -> Tuple[bool, Optional[str]]:
    """
    Require that a ``NOT_AVAILABLE`` fact carries verifiable evidence.

    A reason string alone is not sufficient: the fact must reference an
    existing evidence artifact whose SHA-256 digest matches the stored bytes.
    """
    if not isinstance(fact, dict):
        return False, f"{label} is not a fact object"

    evidence_ref = fact.get("evidence_ref")
    if not isinstance(evidence_ref, dict) or not evidence_ref:
        return False, f"{label} has no evidence reference"

    if evidence_root is None:
        return False, (
            f"{label}: the referenced evidence bytes cannot be verified because no evidence "
            "root was provided"
        )

    ok, error = validate_evidence_ref_bytes(evidence_ref, evidence_root=evidence_root)
    if not ok:
        return False, f"{label}: {error}"
    return True, None


# ---------------------------------------------------------------------------
# Immutable evidence references
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceRef:
    """A pointer to an existing immutable evidence artifact."""

    path: str
    sha256: str
    byte_length: Optional[int] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"path": self.path, "sha256": self.sha256}
        if self.byte_length is not None:
            payload["byte_length"] = self.byte_length
        if self.description:
            payload["description"] = self.description
        return payload


def build_evidence_ref(
    path: os.PathLike | str,
    *,
    description: str = "",
    root: Optional[Path] = None,
) -> Optional[EvidenceRef]:
    """
    Build an :class:`EvidenceRef` for an existing file.

    Returns ``None`` when the artifact does not exist: a reference to a
    non-existent artifact is worse than no reference at all.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return None
    digest = file_sha256(file_path)
    if digest is None:
        return None
    display = str(file_path)
    if root is not None:
        try:
            display = str(file_path.resolve().relative_to(Path(root).resolve())).replace("\\", "/")
        except (ValueError, OSError):
            display = str(file_path)
    return EvidenceRef(
        path=display,
        sha256=digest,
        byte_length=file_path.stat().st_size,
        description=description,
    )


# ---------------------------------------------------------------------------
# Per-stage evidence (Iteration 16)
# ---------------------------------------------------------------------------
#
# Iteration 15 made every NOT_AVAILABLE fact point at a digest-verifiable
# artifact - but all four stages pointed at ONE shared file that held the
# bytes of the EVM and the replay stage only. An inference fact and a
# persistence fact were therefore "proved" with bytes of a different stage.
#
# Iteration 16 gives every stage its own artifact, and every artifact declares
# the stage it belongs to. A fact may only cite the artifact of its own stage,
# and a missing fact must say honestly WHICH of the different kinds of absence
# it is.

#: Schema version of a per-stage evidence artifact.
STAGE_EVIDENCE_SCHEMA_VERSION = "1.0.0"

#: The identity fields a stage may report.
MODAL_IDENTITY_FIELDS = ("app_id", "function_call_id", "container_id")

#: The provider returned a response and the field is absent from it.
ABSENCE_PROVIDER_FIELD_OMITTED = "PROVIDER_FIELD_OMITTED"

#: The stage was never invoked for this target.
ABSENCE_STAGE_NOT_ATTEMPTED = "STAGE_NOT_ATTEMPTED"

#: The stage ran and returned a response, but that response carried no
#: runtime-identity envelope.
ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE = "STAGE_EXECUTED_NO_RUNTIME_ENVELOPE"

#: This client never requested the field from that stage.
ABSENCE_CLIENT_NEVER_CAPTURED_FIELD = "CLIENT_NEVER_CAPTURED_FIELD"

#: The stage was invoked but failed, so no response was received at all.
ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE = "STAGE_ATTEMPT_FAILED_NO_RESPONSE"

#: Every kind of absence the producer may record.
ABSENCE_KINDS = (
    ABSENCE_PROVIDER_FIELD_OMITTED,
    ABSENCE_STAGE_NOT_ATTEMPTED,
    ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE,
    ABSENCE_CLIENT_NEVER_CAPTURED_FIELD,
    ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE,
)

#: Only this kind may claim that the provider did not report a field. The
#: other kinds describe a situation in which the provider was never asked.
ABSENCE_KINDS_THAT_MAY_CLAIM_PROVIDER_OMISSION = (ABSENCE_PROVIDER_FIELD_OMITTED,)

#: Wording that blames the provider for a field the provider was never asked
#: about. It is only allowed for ``PROVIDER_FIELD_OMITTED``.
PROVIDER_OMISSION_PHRASE_RE = re.compile(
    r"(?i)\b(?:never reported|did not report|does not report|not reported|"
    r"did not expose|was not reported|provider did not|runtime did not report)\b"
)

# ---------------------------------------------------------------------------
#
# Iteration 17 closes the last gap of the stage-evidence contract: the flags of
# an artifact and the kind of absence it records were checked one by one, so
# combinations that cannot happen could still pass. A stage that was never
# attempted could claim to have "executed"; a provider omission could be
# claimed for a field the client never asked for; a response without a runtime
# envelope could be recorded as a stage that received no response at all.
#
# The fix is a single state table. The four flags of a stage describe exactly
# one state, every state allows exactly the kinds of absence that can honestly
# occur in it, and the kind that is allowed also fixes what ``requested_fields``
# must say about the field in question.

#: The four flags that describe the state of a stage.
STAGE_FLAG_NAMES = ("attempted", "executed", "response_received", "runtime_envelope_received")

#: The stage was never invoked for this target.
STAGE_STATE_NOT_ATTEMPTED = "NOT_ATTEMPTED"

#: The stage was invoked, but no response came back.
STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE = "ATTEMPT_FAILED_NO_RESPONSE"

#: The stage answered, but it did not complete: the client holds the response
#: and the response carries no runtime-identity envelope.
STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED = "RESPONSE_RECEIVED_NOT_EXECUTED"

#: The stage answered and completed, but the response carried no
#: runtime-identity envelope.
STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE = "EXECUTED_NO_RUNTIME_ENVELOPE"

#: The stage answered, completed, and its response carried a runtime-identity
#: envelope.
STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE = "EXECUTED_WITH_RUNTIME_ENVELOPE"

#: THE state table of a stage: the key is the tuple of the four flags
#: ``(attempted, executed, response_received, runtime_envelope_received)``, the
#: value is the name of the state. A combination that is not in this table
#: cannot happen and is rejected - there is no third way for a stage to be.
STAGE_STATE_TABLE = {
    (False, False, False, False): STAGE_STATE_NOT_ATTEMPTED,
    (True, False, False, False): STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE,
    (True, False, True, False): STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED,
    (True, True, True, False): STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE,
    (True, True, True, True): STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
}

#: The states in which the stage answered, so the client holds a response of
#: that stage.
STAGE_STATES_WITH_RESPONSE = (
    STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED,
    STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE,
    STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
)

#: ``requested_fields`` may say anything about the field.
ABSENCE_REQUESTED_IRRELEVANT = "irrelevant"

#: The field must be listed in ``requested_fields``: the client asked for it.
ABSENCE_REQUESTED_PRESENT = "present"

#: The field must NOT be listed in ``requested_fields``: the client never
#: asked for it.
ABSENCE_REQUESTED_ABSENT = "absent"

#: The rules of every kind of absence: the states the kind may describe and
#: what ``requested_fields`` must say about the field in question.
ABSENCE_KIND_RULES = {
    ABSENCE_STAGE_NOT_ATTEMPTED: {
        "states": (STAGE_STATE_NOT_ATTEMPTED,),
        "requested": ABSENCE_REQUESTED_IRRELEVANT,
    },
    ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE: {
        "states": (STAGE_STATE_ATTEMPT_FAILED_NO_RESPONSE,),
        "requested": ABSENCE_REQUESTED_IRRELEVANT,
    },
    ABSENCE_CLIENT_NEVER_CAPTURED_FIELD: {
        "states": STAGE_STATES_WITH_RESPONSE,
        "requested": ABSENCE_REQUESTED_ABSENT,
    },
    ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE: {
        "states": (
            STAGE_STATE_RESPONSE_RECEIVED_NOT_EXECUTED,
            STAGE_STATE_EXECUTED_NO_RUNTIME_ENVELOPE,
        ),
        "requested": ABSENCE_REQUESTED_PRESENT,
    },
    ABSENCE_PROVIDER_FIELD_OMITTED: {
        "states": (STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,),
        "requested": ABSENCE_REQUESTED_PRESENT,
    },
}


# ---------------------------------------------------------------------------
#
# Iteration 18 binds the captured response to the runtime envelope.
#
# Iteration 17 made the four flags of a stage a state machine, but the payload
# the artifact stores was still checked in one direction only: an artifact that
# claimed "no response" could still hold a provider response, and the runtime
# envelope could be detached from the response it is supposed to come from. A
# malformed identity fact in the envelope was even treated as if the provider
# had simply omitted the field.
#
# Iteration 18 therefore binds three things together: the flag of the stage,
# the payload the artifact stores and the runtime-identity envelope. They are
# three descriptions of one event, so they may not contradict each other.
#
# The producer refuses to write an artifact in which they do not agree, and the
# validator rejects such an artifact even when every digest in it is
# internally consistent.

#: The statuses a documented identity fact may carry.
IDENTITY_FACT_STATUSES = (OBSERVED, NOT_AVAILABLE)


class EvidenceContractError(ValueError):
    """
    The producer was asked to write evidence that would be ambiguous.

    The evidence chain never writes an artifact that says one thing and stores
    another: a contradictory capture, an envelope that the captured response
    does not carry, or an envelope with a malformed identity fact is refused
    instead of being written down.
    """


def _is_observed_fact(fact: Any) -> bool:
    """
    True when a fact is a well-formed ``OBSERVED`` fact with a value.

    The identity fields of a runtime envelope are provider-issued identifiers,
    so an observed value is a non-empty string that names the source it was
    read from.
    """
    if not isinstance(fact, dict) or fact.get("status") != OBSERVED:
        return False
    value = fact.get("value")
    if not isinstance(value, str) or not value.strip():
        return False
    source = fact.get("source")
    return isinstance(source, str) and bool(source.strip())


def validate_observation_side(
    fact: Any,
    *,
    expected_side: Optional[str] = None,
    require_side: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Check that a fact names the side that observed it - and names it correctly.

    * a fact may name only a known side;
    * a fact may not name a side other than the expected one: the envelope of a
      worker response is worker-side by construction, so a client observation
      can never sit inside it;
    * an ``OBSERVED`` fact whose source names the client side may not be
      labelled ``worker``, and a fact whose source names the worker side may
      not be labelled ``client``.

    A ``NOT_AVAILABLE`` fact is **not** restricted by its reason: the reason of
    an absent worker fact is allowed to name the client side as the place where
    the value *is* available.

    A fact that names no side at all is accepted - every artifact of
    Iterations 14-19 has no such name.

    ``require_side`` (Iteration 22) turns that acceptance into an error: in the
    strict mode an ``OBSERVED`` fact that names **no** side does not say who
    observed it, and the side is exactly what the closed registry of the
    observation sources ties to a field. The keyword defaults to ``False``, so
    the compatibility path - the path the side-less artifacts of Iterations
    14-20 are read through - stays exactly as it is.
    """
    if not isinstance(fact, dict):
        return True, None

    declared = fact.get("observed_by")
    if declared is None:
        if require_side and fact.get("status") == OBSERVED:
            return False, (
                "The fact names no observation side: an observed fact has to say whether the "
                f"{OBSERVATION_SIDE_WORKER} or the {OBSERVATION_SIDE_CLIENT} observed it"
            )
        return True, None

    if declared not in OBSERVATION_SIDES:
        return False, (
            f"The fact names the unknown observation side {declared!r}; a fact may name only "
            f"{', '.join(OBSERVATION_SIDES)}"
        )

    if expected_side is not None and declared != expected_side:
        return False, (
            f"The fact names the observation side {declared!r}, but this envelope is "
            f"{expected_side!r}-side: a {expected_side} observation may not be presented as a "
            f"{declared} observation"
        )

    if fact.get("status") != OBSERVED:
        # The reason of an absent fact may name the other side - that is where
        # the value is available.
        return True, None

    source = str(fact.get("source") or "")
    if declared == OBSERVATION_SIDE_WORKER and CLIENT_SIDE_SOURCE_RE.search(source):
        return False, (
            "The fact is labelled as observed by the worker, but its source names the client "
            f"side: {source!r}. A client observation can never be presented as a worker "
            "observation."
        )
    if declared == OBSERVATION_SIDE_CLIENT and WORKER_SIDE_SOURCE_RE.search(source):
        return False, (
            "The fact is labelled as observed by the client, but its source names the worker "
            f"side: {source!r}. A worker observation can never be presented as a client "
            "observation."
        )
    return True, None


def validate_runtime_identity_envelope(
    envelope: Any,
    *,
    expected_side: Optional[str] = OBSERVATION_SIDE_WORKER,
    strict_sources: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Validate the schema of a runtime-identity envelope.

    Every identity field the envelope carries must be a **documented typed
    fact**: an object with a known status and the payload that belongs to that
    status.

    * ``OBSERVED`` needs a non-empty string value and a named source;
    * ``NOT_AVAILABLE`` needs no value and an explicit reason.

    A field that is present but malformed is an **error**. It is never treated
    as a field the provider omitted - the provider did answer, and the answer
    is what has to be checked.

    Only the identity fields of the envelope are validated. The additional
    provider keys the Modal worker returns (``app_page_url``,
    ``container_id_value``) are not identity fields, are not classified and
    are therefore not part of this contract - with one exception: in the
    strict mode the whole registry of the observation sources is checked, and
    the registry knows the client-side ``app_page_url`` as a provider-issued
    identity field (Iteration 22). The raw ``container_id_value`` is no
    provider-issued value and stays outside the contract in every mode.

    ``expected_side`` is the side the envelope itself belongs to (Iteration
    20). The envelope of a worker response is worker-side, so a fact inside it
    may not claim to be a client observation. A fact that names no side at all
    stays valid, so every artifact of Iterations 14-19 remains valid.

    ``strict_sources`` applies the registry of the allowed observation sources
    (Iteration 21): an observed value has to name a **registered** source, the
    registered side and the provider's shape. The mode is opt-in and additive -
    the artifacts of Iterations 14-20 stay valid without it.

    In the strict mode the side is **mandatory** (Iteration 22): an observed
    identity fact has to name the side that observed it, and that side has to
    be the one registered for the field. A missing, a ``null`` and an unknown
    side are rejected, and so is a side that contradicts the registered one.
    Without ``strict_sources`` a side-less fact stays valid - that is the
    compatibility path the artifacts of Iterations 14-20 are read through.
    """
    if envelope is None:
        return True, None
    if not isinstance(envelope, dict):
        return False, "The runtime-identity envelope is not an object"

    # The identity fields of the envelope are the fields of the contract. In
    # the strict mode the whole registry of the observation sources is checked
    # as well (Iteration 22): the registry knows the client-side
    # 'app_page_url' as a provider-issued identity field, and a fact that names
    # no side is not acceptable for any field of it.
    fields_to_check = list(MODAL_IDENTITY_FIELDS)
    if strict_sources:
        for registered_field in PROVIDER_OBSERVATION_SOURCES:
            if registered_field not in fields_to_check:
                fields_to_check.append(registered_field)

    for field_name in fields_to_check:
        if field_name not in envelope:
            continue
        fact = envelope[field_name]
        if not isinstance(fact, dict):
            return False, (
                f"The runtime-identity envelope carries a malformed fact for '{field_name}': "
                f"it is {type(fact).__name__} instead of a typed fact"
            )
        status = fact.get("status")
        if status not in IDENTITY_FACT_STATUSES:
            return False, (
                f"The runtime-identity envelope carries a malformed fact for '{field_name}': "
                f"its status {status!r} is neither {OBSERVED!r} nor {NOT_AVAILABLE!r}"
            )
        ok, error = validate_observation_side(
            fact,
            expected_side=expected_side,
            require_side=strict_sources,
        )
        if not ok:
            return False, (
                f"The runtime-identity envelope carries a malformed fact for '{field_name}': "
                f"{error}"
            )
        if strict_sources:
            ok, error = validate_provider_observation_source(
                field_name,
                fact,
                expected_side=expected_side,
                require_side=True,
            )
            if not ok:
                return False, (
                    f"The runtime-identity envelope carries a malformed fact for '{field_name}': "
                    f"{error}"
                )
        if status == OBSERVED:
            value = fact.get("value")
            if not isinstance(value, str) or not value.strip():
                return False, (
                    f"The runtime-identity envelope carries a malformed fact for '{field_name}': "
                    "an observed identity value must be a non-empty string"
                )
            source = fact.get("source")
            if not isinstance(source, str) or not source.strip():
                return False, (
                    f"The runtime-identity envelope carries a malformed fact for '{field_name}': "
                    "an observed fact must name the source it was read from"
                )
            continue
        if fact.get("value") is not None:
            return False, (
                f"The runtime-identity envelope carries a malformed fact for '{field_name}': "
                f"a {NOT_AVAILABLE} fact must not hold a value"
            )
        reason = fact.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return False, (
                f"The runtime-identity envelope carries a malformed fact for '{field_name}': "
                f"a {NOT_AVAILABLE} fact must state the reason"
            )
    return True, None


def _validate_capture(capture: StageResponseCapture) -> None:
    """
    Check that the capture of a stage describes one coherent thing.

    The capture is the raw material of the stage evidence artifact: the flags,
    the payload and the runtime-identity envelope have to agree before
    anything is written. A capture that contradicts itself is refused - the
    producer never writes an artifact that says one thing and stores another.
    """
    if capture.response_received and capture.provider_response is None:
        raise EvidenceContractError(
            f"The {capture.stage} stage claims that a response was received but the capture "
            "holds no payload"
        )
    if not capture.response_received and capture.provider_response is not None:
        raise EvidenceContractError(
            f"The {capture.stage} stage claims that no response was received but the capture "
            "holds a payload"
        )

    if capture.runtime_identity is not None:
        if not capture.response_received:
            raise EvidenceContractError(
                f"The {capture.stage} stage holds a runtime-identity envelope although it "
                "received no response"
            )
        source = capture.runtime_identity_source
        if not source:
            raise EvidenceContractError(
                f"The {capture.stage} stage holds a runtime-identity envelope but does not say "
                "where it came from"
            )
        if not isinstance(capture.provider_response, dict):
            raise EvidenceContractError(
                f"The {capture.stage} stage holds a runtime-identity envelope but its captured "
                "response is not an object and can therefore not carry it"
            )
        if source not in capture.provider_response:
            raise EvidenceContractError(
                f"The captured response of the {capture.stage} stage does not contain the "
                f"runtime-identity envelope at {source!r}"
            )
        if canonical_json_bytes(capture.provider_response[source]) != canonical_json_bytes(
            capture.runtime_identity
        ):
            raise EvidenceContractError(
                f"The runtime-identity envelope of the {capture.stage} stage is not the one its "
                "captured response carries"
            )

    ok, error = validate_runtime_identity_envelope(capture.runtime_identity)
    if not ok:
        raise EvidenceContractError(f"The {capture.stage} stage: {error}")


def validate_stage_capture(
    capture: StageResponseCapture,
) -> Tuple[bool, Optional[str]]:
    """
    Check that the capture of a stage describes one coherent thing.

    The public counterpart of the producer-side contract: a caller that wants
    to know whether a capture may be written down asks this function first.
    """
    try:
        _validate_capture(capture)
    except EvidenceContractError as exc:
        return False, str(exc)
    return True, None


def _json_default(value: Any) -> Any:
    """Encode the values a provider payload may contain into canonical JSON."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=lambda item: str(item))
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, Path):
        return str(value)
    return str(value)


def canonical_json_bytes(value: Any) -> bytes:
    """
    The deterministic UTF-8 encoding every evidence digest is computed over.

    Enumerations become their value, sets become sorted lists and bytes become
    base64 text, so the same provider payload always produces the same bytes
    and therefore the same digest - no matter where it is re-serialized.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


@dataclass
class StageResponseCapture:
    """
    What one stage's provider response actually was for this client.

    The capture is the raw material of a per-stage evidence artifact: it holds
    the payload the provider returned (as the object the SDK returned it), the
    runtime-identity envelope that was (or was not) part of it, and the flags
    that describe the stage.

    The digest of the payload is computed over the **canonical JSON
    serialization** of that object, not over the raw transport bytes the
    provider sent over the wire.
    """

    stage: str
    attempted: bool
    executed: bool
    response_received: bool
    provider_response: Any = None
    runtime_identity: Optional[Dict[str, Any]] = None
    runtime_identity_source: str = ""
    response_source: str = ""
    requested_fields: Sequence[str] = MODAL_IDENTITY_FIELDS


def _observed_identity_value(
    runtime_identity: Optional[Dict[str, Any]],
    field_name: str,
) -> Tuple[Optional[Any], str]:
    """
    Return the observed value of an identity field, or ``(None, "")``.

    Only a well-formed ``OBSERVED`` fact counts as an observation. A fact that
    is present but malformed is not an observation - and the envelope check of
    Iteration 18 rejects the artifact that carries it, so it can never be
    mistaken for a field the provider omitted.
    """
    if not isinstance(runtime_identity, dict):
        return None, ""
    fact = runtime_identity.get(field_name)
    if _is_observed_fact(fact):
        return fact.get("value"), str(fact.get("source") or "")
    return None, ""


def _observed_identity_side(
    runtime_identity: Optional[Dict[str, Any]],
    field_name: str,
) -> Optional[str]:
    """
    The side that observed an identity field, or ``None``.

    The side is the one the envelope declared for that field. A field the
    envelope did not declare a side for keeps no side here as well - the fact
    of a stage is exactly as explicit as the envelope it was derived from
    (Iteration 20).
    """
    if not isinstance(runtime_identity, dict):
        return None
    fact = runtime_identity.get(field_name)
    if not _is_observed_fact(fact):
        return None
    side = fact.get("observed_by")
    return str(side) if side in OBSERVATION_SIDES else None


def _provider_absence_reason(
    runtime_identity: Optional[Dict[str, Any]],
    field_name: str,
) -> str:
    """Return the provider's own reason for a field it marked unavailable."""
    if not isinstance(runtime_identity, dict):
        return ""
    fact = runtime_identity.get(field_name)
    if isinstance(fact, dict) and fact.get("status") == NOT_AVAILABLE:
        return str(fact.get("reason") or "").strip()
    return ""


def classify_absence_kind(
    *,
    attempted: bool,
    response_received: bool,
    requested_fields: Sequence[str],
    runtime_identity: Optional[Dict[str, Any]],
    field_name: str,
) -> Optional[str]:
    """
    The kind of absence of one identity field, derived from the state.

    This is the single classifier of the evidence chain. The producer uses it
    to write the absence records of an artifact, and the validator uses it to
    check them. Because both sides call this one function, a record can never
    claim a kind that the state of its own artifact does not allow.

    ``None`` means the field was observed - there is no absence at all.
    """
    value, _source = _observed_identity_value(runtime_identity, field_name)
    if value is not None:
        return None

    if not attempted:
        return ABSENCE_STAGE_NOT_ATTEMPTED

    if not response_received:
        return ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE

    if field_name not in tuple(requested_fields):
        return ABSENCE_CLIENT_NEVER_CAPTURED_FIELD

    if runtime_identity is None:
        return ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE

    return ABSENCE_PROVIDER_FIELD_OMITTED


def _absence_reason(capture: StageResponseCapture, field_name: str, kind: str) -> str:
    """The reason that belongs to one kind of absence."""
    if kind == ABSENCE_STAGE_NOT_ATTEMPTED:
        return (
            f"the {capture.stage} stage was not attempted for this target, so no response was "
            f"ever requested for '{field_name}'"
        )

    if kind == ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE:
        return (
            f"the {capture.stage} stage was attempted but returned no response, so this client "
            f"holds no '{field_name}' for this target"
        )

    if kind == ABSENCE_CLIENT_NEVER_CAPTURED_FIELD:
        return (
            f"this client never requested '{field_name}' from the {capture.stage} stage, so the "
            f"field was never captured"
        )

    if kind == ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE:
        return (
            f"the {capture.stage} stage returned a response that carried no runtime-identity "
            f"envelope, so this client holds no '{field_name}' for this target"
        )

    provider_reason = _provider_absence_reason(capture.runtime_identity, field_name)
    return provider_reason or (
        f"the provider's response for the {capture.stage} stage does not contain "
        f"'{field_name}'"
    )


def classify_stage_absence(
    capture: StageResponseCapture,
    field_name: str,
) -> Tuple[Optional[str], str]:
    """
    Classify why an identity field is missing from one stage's response.

    Returns ``(None, "")`` when the field was actually observed, otherwise the
    machine-readable kind of the absence together with the reason.

    The order of the checks is the order of the truth: a stage that never ran
    cannot have been refused by the provider, and a field the client never
    asked for was never refused by anybody.
    """
    kind = classify_absence_kind(
        attempted=capture.attempted,
        response_received=capture.response_received,
        requested_fields=capture.requested_fields,
        runtime_identity=capture.runtime_identity,
        field_name=field_name,
    )
    if kind is None:
        return None, ""
    return kind, _absence_reason(capture, field_name, kind)


def build_stage_evidence_artifact(
    capture: StageResponseCapture,
    *,
    target_id: str,
    correlation_id: str,
) -> Dict[str, Any]:
    """
    Build the evidence artifact of exactly one stage.

    The artifact holds the payload that stage returned, the metadata that
    describes it, and one typed absence record per identity field that is
    missing. The ``stage`` field is what binds the artifact to the facts that
    are allowed to cite it.

    The digest of the payload is computed over the canonical JSON
    serialization of the returned object - it describes the bytes that are
    stored inside the artifact and can be recomputed from them. It is **not**
    the digest of the raw transport bytes the provider sent.

    The capture is validated before anything is written: a capture whose flags,
    payload and envelope contradict each other is refused
    (``EvidenceContractError``) instead of being written down.
    """
    _validate_capture(capture)

    absence_records: List[Dict[str, Any]] = []
    for field_name in MODAL_IDENTITY_FIELDS:
        kind, reason = classify_stage_absence(capture, field_name)
        if kind is None:
            continue
        absence_records.append({"kind": kind, "field": field_name, "reason": reason})

    provider_bytes = (
        canonical_json_bytes(capture.provider_response)
        if capture.response_received
        else None
    )
    runtime_bytes = (
        canonical_json_bytes(capture.runtime_identity)
        if capture.runtime_identity is not None
        else None
    )

    return {
        "schema_version": STAGE_EVIDENCE_SCHEMA_VERSION,
        "stage": capture.stage,
        "target_id": target_id,
        "correlation_id": correlation_id,
        "attempted": bool(capture.attempted),
        "executed": bool(capture.executed),
        "response_received": bool(capture.response_received),
        "runtime_envelope_received": capture.runtime_identity is not None,
        "requested_fields": list(capture.requested_fields),
        "provider_response": capture.provider_response,
        "runtime_identity": capture.runtime_identity,
        # The source of the envelope is recorded only when an envelope was
        # received: an artifact that names the source of an envelope it does
        # not hold would leave the reader guessing (Iteration 18).
        "runtime_identity_source": (
            capture.runtime_identity_source if capture.runtime_identity is not None else ""
        ),
        "provider_response_metadata": {
            # The metadata of a response describes a response that was really
            # captured. A stage that received no response has no digest, no
            # byte length and no source - the digest of the JSON literal
            # ``null`` is not the digest of a captured response (Iteration 18).
            "response_source": capture.response_source if capture.response_received else "",
            "response_sha256": sha256_bytes(provider_bytes) if provider_bytes is not None else None,
            "response_byte_length": len(provider_bytes) if provider_bytes is not None else None,
            "runtime_identity_sha256": sha256_bytes(runtime_bytes) if runtime_bytes else None,
            "runtime_identity_byte_length": len(runtime_bytes) if runtime_bytes else None,
        },
        "absence_records": absence_records,
    }


def write_stage_evidence_artifact(
    directory: os.PathLike | str,
    capture: StageResponseCapture,
    *,
    target_id: str,
    correlation_id: str,
) -> Tuple[Path, Dict[str, Any]]:
    """Write one stage's evidence artifact and describe its exact bytes."""
    artifact = build_stage_evidence_artifact(
        capture, target_id=target_id, correlation_id=correlation_id
    )
    data = json.dumps(
        artifact,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")
    name = f"{target_id}_stage_evidence_{capture.stage}.json"
    path = Path(directory) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    evidence_ref = build_evidence_ref_from_bytes(
        name,
        data,
        description=(
            f"the exact response the {capture.stage} stage returned for this target"
        ),
    )
    return path, evidence_ref


def build_stage_identity_facts(
    capture: StageResponseCapture,
    *,
    evidence_ref: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build the identity facts of one stage.

    Every missing field carries its kind of absence and the evidence reference
    of the artifact that proves the absence - the artifact of this stage and of
    no other stage.

    The capture is validated first: a capture whose flags, payload and
    envelope contradict each other is refused (``EvidenceContractError``), so
    no fact is ever derived from a capture that contradicts itself.
    """
    _validate_capture(capture)

    facts: Dict[str, Any] = {}
    for field_name in MODAL_IDENTITY_FIELDS:
        kind, reason = classify_stage_absence(capture, field_name)
        if kind is None:
            value, source = _observed_identity_value(capture.runtime_identity, field_name)
            facts[field_name] = observed(
                value,
                source=source or f"the provider response of the {capture.stage} stage",
                # The side of the observation is the side the envelope declared
                # for that field: a worker-side fact stays worker-side
                # (Iteration 20).
                observed_by=_observed_identity_side(capture.runtime_identity, field_name),
            )
            continue
        facts[field_name] = not_available(
            reason,
            evidence_ref=evidence_ref,
            absence_kind=kind,
        )
    return facts


def _stage_state_of(payload: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    The state the four flags of an artifact describe.

    Returns ``(state, None)`` for a state the table knows and ``(None, error)``
    for a combination of the flags that cannot happen.
    """
    flags = (
        bool(payload.get("attempted")),
        bool(payload.get("executed")),
        bool(payload.get("response_received")),
        bool(payload.get("runtime_envelope_received")),
    )
    state = STAGE_STATE_TABLE.get(flags)
    if state is None:
        possible = ", ".join(sorted(STAGE_STATE_TABLE.values()))
        return None, (
            "The stage evidence artifact describes an impossible state: attempted={attempted}, "
            "executed={executed}, response_received={response_received}, "
            "runtime_envelope_received={envelope}. The possible states are: {states}.".format(
                attempted=flags[0],
                executed=flags[1],
                response_received=flags[2],
                envelope=flags[3],
                states=possible,
            )
        )
    return state, None


def _check_absence_record_against_flags(
    payload: Dict[str, Any],
    record: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """
    Check that one absence record agrees with the state of its artifact.

    Three things are checked: the kind must be one the state of the stage
    allows, the ``requested_fields`` of the artifact must agree with the kind,
    and a provider omission must really be an omission in the captured
    envelope.
    """
    kind = record["kind"]
    field_name = record["field"]
    requested_fields = payload.get("requested_fields") or []

    state, state_error = _stage_state_of(payload)
    if state_error is not None:
        return False, state_error

    rule = ABSENCE_KIND_RULES.get(kind)
    if rule is None:
        return False, f"A stage evidence absence record has the unknown kind {kind!r}"

    if state not in rule["states"]:
        return False, (
            f"The stage evidence artifact records '{field_name}' as {kind} although the state "
            f"of the stage is {state}"
        )

    if rule["requested"] == ABSENCE_REQUESTED_PRESENT and field_name not in requested_fields:
        return False, (
            f"The stage evidence artifact records '{field_name}' as omitted by the provider "
            "although this client never requested that field"
        )
    if rule["requested"] == ABSENCE_REQUESTED_ABSENT and field_name in requested_fields:
        return False, (
            f"The stage evidence artifact records '{field_name}' as never requested although "
            "the client asked for it"
        )

    if kind == ABSENCE_PROVIDER_FIELD_OMITTED:
        if not payload.get("response_received"):
            return False, (
                f"The stage evidence artifact records '{field_name}' as omitted by the provider "
                "although the stage received no response"
            )
        envelope = payload.get("runtime_identity")
        if not isinstance(envelope, dict):
            return False, (
                f"The stage evidence artifact records '{field_name}' as omitted by the provider "
                "although no runtime-identity envelope was received"
            )
        if field_name in envelope:
            value = envelope.get(field_name)
            if _is_observed_fact(value):
                return False, (
                    f"The stage evidence artifact records '{field_name}' as omitted by the "
                    "provider although the provider reported it"
                )
            if not (isinstance(value, dict) and value.get("status") == NOT_AVAILABLE):
                # A field that is present but malformed is not an omission:
                # the provider answered something that cannot be checked, and
                # that must never be re-labelled as "the provider omitted it"
                # (Iteration 18).
                return False, (
                    f"The stage evidence artifact records '{field_name}' as omitted by the "
                    "provider although the runtime-identity envelope carries a malformed fact "
                    "for it"
                )

    if kind not in ABSENCE_KINDS_THAT_MAY_CLAIM_PROVIDER_OMISSION:
        if PROVIDER_OMISSION_PHRASE_RE.search(str(record.get("reason") or "")):
            return False, (
                f"The stage evidence artifact claims the provider did not report '{field_name}', "
                "but the provider was never asked for that field"
            )
    return True, None


def validate_stage_evidence_artifact(
    payload: Any,
    *,
    expected_stage: str,
) -> Tuple[bool, Optional[str]]:
    """
    Validate the internal consistency of one per-stage evidence artifact.

    The artifact must declare the stage it is used for, must describe the
    returned payload in a way that can be recomputed from the stored bytes, and
    every absence record must agree with the flags of the artifact itself.
    """
    if not isinstance(payload, dict) or not payload:
        return False, "The stage evidence artifact is missing or empty"

    schema_version = payload.get("schema_version")
    if schema_version != STAGE_EVIDENCE_SCHEMA_VERSION:
        return False, (
            f"The stage evidence artifact has schema version {schema_version!r}, expected "
            f"{STAGE_EVIDENCE_SCHEMA_VERSION!r}"
        )

    stage = payload.get("stage")
    if stage != expected_stage:
        return False, (
            f"The stage evidence artifact declares the stage {stage!r} but is used for the "
            f"stage {expected_stage!r}"
        )

    for key in ("attempted", "executed", "response_received", "runtime_envelope_received"):
        if not isinstance(payload.get(key), bool):
            return False, f"The stage evidence artifact has no boolean '{key}'"

    # The four flags must describe a state that can exist. This is the state
    # table of the stage: every combination that is not in it is impossible and
    # is rejected before any absence record is looked at.
    state, state_error = _stage_state_of(payload)
    if state_error is not None:
        return False, state_error

    requested_fields = payload.get("requested_fields")
    if not isinstance(requested_fields, list) or not all(
        isinstance(item, str) for item in requested_fields
    ):
        return False, "The stage evidence artifact has no valid 'requested_fields' list"

    metadata = payload.get("provider_response_metadata")
    if not isinstance(metadata, dict):
        return False, "The stage evidence artifact has no 'provider_response_metadata'"

    provider_response = payload.get("provider_response")
    if payload.get("response_received"):
        if provider_response is None:
            return False, (
                "The stage evidence artifact claims that a response was received but holds none"
            )
    elif provider_response is not None:
        # The flag and the payload are two descriptions of one fact: a stage
        # that received no response may not store one (Iteration 18).
        return False, (
            "The stage evidence artifact claims that no response was received but holds a "
            "provider response"
        )

    if payload.get("response_received"):
        expected_digest = sha256_bytes(canonical_json_bytes(provider_response))
        if metadata.get("response_sha256") != expected_digest:
            return False, (
                "The recorded digest of the returned payload does not match the payload stored in "
                "the stage evidence artifact"
            )
        expected_length = len(canonical_json_bytes(provider_response))
        if metadata.get("response_byte_length") != expected_length:
            return False, (
                "The recorded byte length of the returned payload does not match the payload "
                "stored in the stage evidence artifact"
            )
        if not str(metadata.get("response_source") or "").strip():
            return False, (
                "The stage evidence artifact holds a provider response but does not say where "
                "that response came from"
            )
    else:
        # The metadata of a response describes a response that was really
        # captured. A stage that received none has no digest, no byte length
        # and no source (Iteration 18).
        if (
            metadata.get("response_sha256") is not None
            or metadata.get("response_byte_length") is not None
            or str(metadata.get("response_source") or "").strip()
        ):
            return False, (
                "The stage evidence artifact claims that no response was received but its "
                "response metadata implies that a response was captured"
            )

    runtime_identity = payload.get("runtime_identity")
    if payload.get("runtime_envelope_received"):
        if not isinstance(runtime_identity, dict):
            return False, (
                "The stage evidence artifact claims a runtime-identity envelope but holds none"
            )
        # The schema of the envelope is checked before a single absence record
        # is classified: a malformed identity fact is an error and must never
        # be downgraded to "the provider omitted this field" (Iteration 18).
        envelope_ok, envelope_error = validate_runtime_identity_envelope(runtime_identity)
        if not envelope_ok:
            return False, envelope_error
        expected_runtime_digest = sha256_bytes(canonical_json_bytes(runtime_identity))
        if metadata.get("runtime_identity_sha256") != expected_runtime_digest:
            return False, (
                "The recorded digest of the runtime-identity envelope does not match the "
                "envelope stored in the stage evidence artifact"
            )
        source = payload.get("runtime_identity_source")
        if not source:
            return False, (
                "The stage evidence artifact holds a runtime-identity envelope but does not say "
                "where it came from"
            )
        # The envelope belongs to the captured response. The binding is checked
        # for EVERY shape of the response: a payload that is not an object
        # cannot carry an envelope and is rejected, not skipped (Iteration 18).
        if not isinstance(provider_response, dict):
            return False, (
                "The captured response of the stage is not an object and can therefore not "
                f"carry the runtime-identity envelope at {source!r}"
            )
        if source not in provider_response:
            return False, (
                f"The returned payload of the stage does not contain the runtime-identity "
                f"envelope at {source!r}"
            )
        if canonical_json_bytes(provider_response[source]) != canonical_json_bytes(
            runtime_identity
        ):
            return False, (
                "The runtime-identity envelope of the stage evidence artifact is not the "
                "one the returned payload carries"
            )
    else:
        if runtime_identity is not None:
            return False, (
                "The stage evidence artifact holds a runtime-identity envelope although it claims "
                "that none was received"
            )
        if str(payload.get("runtime_identity_source") or "").strip():
            return False, (
                "The stage evidence artifact names the source of a runtime-identity envelope it "
                "does not hold"
            )

    absence_records = payload.get("absence_records")
    if not isinstance(absence_records, list):
        return False, "The stage evidence artifact has no 'absence_records' list"

    records_by_field: Dict[str, List[Dict[str, Any]]] = {}
    for record in absence_records:
        if not isinstance(record, dict):
            return False, "A stage evidence absence record is not an object"
        kind = record.get("kind")
        if kind not in ABSENCE_KINDS:
            return False, f"A stage evidence absence record has the unknown kind {kind!r}"
        field_name = record.get("field")
        if field_name not in MODAL_IDENTITY_FIELDS:
            return False, (
                f"A stage evidence absence record names the unknown field {field_name!r}"
            )
        if not str(record.get("reason") or "").strip():
            return False, (
                f"A stage evidence absence record for '{field_name}' has no reason"
            )
        ok, error = _check_absence_record_against_flags(payload, record)
        if not ok:
            return False, error
        records_by_field.setdefault(field_name, []).append(record)

    # The set of absence records must be complete and unique: every identity
    # field that the state of the artifact leaves unavailable has exactly one
    # record with exactly the kind the state allows, and every field the
    # provider reported has none. An artifact may not leave a field
    # unaccounted for, and it may not account for the same field twice.
    for field_name in MODAL_IDENTITY_FIELDS:
        expected_kind = classify_absence_kind(
            attempted=bool(payload.get("attempted")),
            response_received=bool(payload.get("response_received")),
            requested_fields=requested_fields,
            runtime_identity=payload.get("runtime_identity"),
            field_name=field_name,
        )
        field_records = records_by_field.get(field_name, [])
        if len(field_records) > 1:
            return False, (
                f"The stage evidence artifact holds {len(field_records)} absence records for "
                f"'{field_name}' although every field has exactly one kind of absence"
            )
        if expected_kind is None:
            if field_records:
                return False, (
                    f"The stage evidence artifact holds an absence record for '{field_name}' "
                    "although the provider reported that field"
                )
            continue
        if not field_records:
            return False, (
                f"The stage evidence artifact holds no absence record for '{field_name}' "
                f"although the state of the stage makes it {expected_kind}"
            )
        recorded_kind = field_records[0].get("kind")
        if recorded_kind != expected_kind:
            return False, (
                f"The stage evidence artifact records '{field_name}' as {recorded_kind!r} "
                f"although the state of the stage makes it {expected_kind!r}"
            )

    return True, None


def validate_stage_evidence_binding(
    stage_name: str,
    stage: Dict[str, Any],
    *,
    evidence_root: os.PathLike | str,
) -> Tuple[bool, Optional[str]]:
    """
    Validate that a stage is backed by the evidence artifact of that stage.

    Three things are checked:

    1. the artifact of the stage exists, its digest matches the stored bytes and
       the artifact declares this very stage;
    2. every unavailable field of the stage cites *that* artifact - an EVM
       artifact can never back an inference fact;
    3. the kind of absence on the fact agrees with the artifact's own absence
       record, and only a provider omission may blame the provider.
    """
    if not isinstance(stage, dict):
        return False, f"Modal provenance stage '{stage_name}' is not an object"

    identity_facts = {key: stage.get(key) for key in MODAL_IDENTITY_FIELDS}
    unavailable_facts = {
        key: fact
        for key, fact in identity_facts.items()
        if isinstance(fact, dict) and fact.get("status") == NOT_AVAILABLE
    }

    declared_ref = stage.get("evidence_ref")
    if not (isinstance(declared_ref, dict) and declared_ref.get("path")):
        declared_ref = None

    fact_refs = {
        key: fact.get("evidence_ref")
        for key, fact in unavailable_facts.items()
        if isinstance(fact.get("evidence_ref"), dict) and fact["evidence_ref"].get("path")
    }

    if declared_ref is not None:
        stage_ref: Optional[Dict[str, Any]] = declared_ref
    elif fact_refs:
        distinct_paths = {ref.get("path") for ref in fact_refs.values()}
        if len(distinct_paths) > 1:
            return False, (
                f"Modal provenance stage '{stage_name}' cites {len(distinct_paths)} different "
                "evidence artifacts; every unavailable field of a stage must be backed by the "
                "evidence of that stage"
            )
        stage_ref = next(iter(fact_refs.values()))
    elif unavailable_facts:
        return False, (
            f"Modal provenance stage '{stage_name}' records an unavailable field without an "
            "evidence reference for its own stage"
        )
    else:
        # Nothing is claimed to be missing in this stage: there is nothing to bind.
        return True, None

    ok, error = validate_evidence_ref_bytes(stage_ref, evidence_root=evidence_root)
    if not ok:
        return False, f"Modal provenance stage '{stage_name}': {error}"

    resolved = resolve_evidence_path(stage_ref.get("path"), evidence_root=evidence_root)
    if resolved is None or not resolved.is_file():
        return False, (
            f"Modal provenance stage '{stage_name}': the stage evidence artifact cannot be read"
        )
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, (
            f"Modal provenance stage '{stage_name}': the stage evidence artifact is not readable "
            "JSON"
        )

    ok, error = validate_stage_evidence_artifact(payload, expected_stage=stage_name)
    if not ok:
        return False, f"Modal provenance stage '{stage_name}': {error}"

    records = {
        record["field"]: record
        for record in payload.get("absence_records", [])
        if isinstance(record, dict) and "field" in record
    }

    for key, fact in unavailable_facts.items():
        fact_ref = fact.get("evidence_ref")
        if not isinstance(fact_ref, dict) or not fact_ref.get("path"):
            return False, (
                f"Modal provenance stage '{stage_name}' records '{key}' as NOT_AVAILABLE without "
                "an evidence reference"
            )
        if fact_ref.get("path") != stage_ref.get("path"):
            return False, (
                f"Modal provenance stage '{stage_name}' records '{key}' as NOT_AVAILABLE but "
                "references the evidence of another stage"
            )

        record = records.get(key)
        if record is None:
            return False, (
                f"The stage evidence artifact of stage '{stage_name}' holds no absence record "
                f"for '{key}'"
            )

        kind = fact.get("absence_kind")
        if kind is not None and kind not in ABSENCE_KINDS:
            return False, (
                f"Modal provenance stage '{stage_name}' records the absence of '{key}' with the "
                f"unknown kind {kind!r}"
            )
        if kind and kind != record.get("kind"):
            return False, (
                f"Modal provenance stage '{stage_name}' classifies the absence of '{key}' as "
                f"{kind!r} while its own evidence records {record.get('kind')!r}"
            )
        # A fact that does not name its kind inherits the one its own stage
        # evidence records - the digest-verified artifact is the authority.
        effective_kind = kind or record.get("kind")
        if effective_kind not in ABSENCE_KINDS_THAT_MAY_CLAIM_PROVIDER_OMISSION:
            if PROVIDER_OMISSION_PHRASE_RE.search(str(fact.get("reason") or "")):
                return False, (
                    f"Modal provenance stage '{stage_name}' claims the provider did not report "
                    f"'{key}', but the stage's own evidence says the field was never requested "
                    "from the provider"
                )

    return True, None


# ---------------------------------------------------------------------------
# P0.1 - Modal invocation provenance
# ---------------------------------------------------------------------------

#: Stages that may appear in the Modal invocation provenance block.
MODAL_PROVENANCE_STAGES = ("inference", "evm_sandbox", "independent_replay", "trajectory_persistence")
#: Optional refinement stages appended when closed-loop refinement runs.
OPTIONAL_MODAL_PROVENANCE_STAGES = ("refinement", "evm_sandbox_after_refinement")


def build_modal_stage_provenance(
    *,
    function_name: Optional[str],
    app_id: Any,
    function_call_id: Any,
    container_id: Any,
    resource: Optional[str],
    attempted: bool,
    evidence_ref: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build the provenance block of a single Modal stage.

    ``app_id`` / ``function_call_id`` / ``container_id`` are either observed
    values or :func:`not_available` facts produced by the caller. No value is
    ever synthesised here.

    ``evidence_ref`` points at the evidence artifact of *this* stage (the exact
    response the stage returned). It is what binds the stage to its own bytes.
    """
    stage: Dict[str, Any] = {
        "attempted": bool(attempted),
        "function_name": function_name,
        "resource": resource,
        "app_id": app_id,
        "function_call_id": function_call_id,
        "container_id": container_id,
    }
    if evidence_ref:
        stage["evidence_ref"] = (
            evidence_ref.to_dict() if hasattr(evidence_ref, "to_dict") else dict(evidence_ref)
        )
    return stage


#: The shape of the provider's own dashboard URL of an app.
MODAL_APP_PAGE_URL_RE = re.compile(r"^https://modal\.com/id/ap-[A-Za-z0-9]{8,}$")


# ---------------------------------------------------------------------------
# The allowed observation sources (Iteration 21)
# ---------------------------------------------------------------------------
#
# The review of Iteration 20 established that an observed value was accepted
# on the strength of its **shape** and a **free-form source string**. A string
# that a test could set was therefore enough to pass as a provider-issued
# identity.
#
# The registry below closes that hole: every identity field has exactly one
# registered source, exactly one side it may be observed from, and exactly one
# shape its value has to have. A value that does not name a registered source
# is not provider-issued - whatever it looks like.
#
# The registry is **additive**: the strict mode is opt-in, so every artifact of
# Iterations 14-20 stays valid and no existing assertion is weakened.

#: The source of the function-call id a worker observes.
SOURCE_WORKER_FUNCTION_CALL_ID = "modal.current_function_call_id()"

#: The source of the application id the client observes.
SOURCE_CLIENT_APP_ID = (
    "the provider-issued App.app_id of the running app (Modal SDK 1.5.5, client side)"
)

#: The source of the app page URL the client observes.
SOURCE_CLIENT_APP_PAGE_URL = (
    "the provider's own dashboard URL of the running app "
    "(App.get_dashboard_url(), Modal SDK 1.5.5, client side)"
)

#: The source of the container id the client observes.
#:
#: The container id of an invocation is a **client-side** fact: the client
#: resolves the function-call id the worker observed through the provider's own
#: call graph (``FunctionCall.get_call_graph()``) and confirms it against the
#: provider's container listing (``TaskList``) and task record (``TaskGetInfo``).
SOURCE_CLIENT_CONTAINER_ID = (
    "the provider's call graph (FunctionCall.get_call_graph) and container listing "
    "(TaskList) of Modal SDK 1.5.5, client side"
)


#: Every identity field, the source that may back an observed value of it,
#: the side it may be observed from and the shape its value has to have.
PROVIDER_OBSERVATION_SOURCES: Dict[str, Dict[str, Any]] = {
    "function_call_id": {
        "source": SOURCE_WORKER_FUNCTION_CALL_ID,
        "side": OBSERVATION_SIDE_WORKER,
        "value_re": MODAL_FUNCTION_CALL_ID_RE,
    },
    "app_id": {
        "source": SOURCE_CLIENT_APP_ID,
        "side": OBSERVATION_SIDE_CLIENT,
        "value_re": MODAL_APP_ID_RE,
    },
    "app_page_url": {
        "source": SOURCE_CLIENT_APP_PAGE_URL,
        "side": OBSERVATION_SIDE_CLIENT,
        "value_re": MODAL_APP_PAGE_URL_RE,
    },
    "container_id": {
        "source": SOURCE_CLIENT_CONTAINER_ID,
        "side": OBSERVATION_SIDE_CLIENT,
        "value_re": MODAL_PROVIDER_CONTAINER_ID_RE,
    },
}


def validate_provider_observation_source(
    field_name: str,
    fact: Any,
    *,
    expected_side: Optional[str] = None,
    require_side: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Check that an observed value names a **registered** observation source.

    A free-form source string is not enough (Iteration 21): only the sources
    of :data:`PROVIDER_OBSERVATION_SOURCES` back a provider-issued value. The
    registered side has to be the side the observation declares, and the value
    has to have the provider's shape.

    A fact that is ``NOT_AVAILABLE`` carries no value and is therefore not
    restricted by this rule - the absence itself is checked elsewhere.

    ``require_side`` (Iteration 22) makes the side **mandatory**: the fact has
    to name the side that observed it, the side has to be a known one, and it
    has to be **exactly** the side registered for the field. Without the
    keyword the side is only compared when the fact happens to name one -
    which is what the compatibility path needs for the side-less artifacts of
    Iterations 14-20.
    """
    if not isinstance(fact, dict):
        return False, f"The fact for '{field_name}' is not a typed fact"

    if fact.get("status") != OBSERVED:
        return True, None

    registered = PROVIDER_OBSERVATION_SOURCES.get(field_name)
    if registered is None:
        return False, (
            f"'{field_name}' is not a provider-issued identity field, so no observed value "
            "of it can be provider-backed"
        )

    source = fact.get("source")
    if source != registered["source"]:
        return False, (
            f"The fact for '{field_name}' names the source {source!r}, which is not a "
            f"registered observation source. The only registered source of '{field_name}' is "
            f"{registered['source']!r}."
        )

    declared = fact.get("observed_by")
    if require_side:
        # Iteration 22: the side is not optional in the strict mode. A fact that
        # names no side at all does not say who observed it, and the registered
        # source of the field says which side may observe it.
        if declared is None:
            return False, (
                f"The fact for '{field_name}' names no observation side: an observed value has "
                f"to say which side observed it - the registered source of '{field_name}' may "
                f"only be observed from the {registered['side']!r} side"
            )
        if declared not in OBSERVATION_SIDES:
            return False, (
                f"The fact for '{field_name}' declares the unknown observation side "
                f"{declared!r}; a fact may name only {', '.join(OBSERVATION_SIDES)}"
            )
        if declared != registered["side"]:
            return False, (
                f"The fact for '{field_name}' declares the observation side {declared!r}, but the "
                f"registered source {registered['source']!r} may only be observed from the "
                f"{registered['side']!r} side"
            )
    elif declared is not None and declared != registered["side"]:
        return False, (
            f"The fact for '{field_name}' declares the observation side {declared!r}, but the "
            f"registered source {registered['source']!r} may only be observed from the "
            f"{registered['side']!r} side"
        )

    if expected_side is not None and declared is not None and declared != expected_side:
        return False, (
            f"The fact for '{field_name}' declares the observation side {declared!r}, but this "
            f"envelope is {expected_side!r}-side"
        )

    value = fact.get("value")
    if not isinstance(value, str) or not value.strip():
        return False, f"The fact for '{field_name}' holds no usable value"
    if not registered["value_re"].fullmatch(value):
        return False, (
            f"The observed value of '{field_name}' is not a provider-issued identifier of the "
            f"registered shape: {value!r}"
        )
    return True, None


def validate_client_container_correlation(
    fact: Any,
    *,
    expected_function_call_id: Optional[str] = None,
    expected_app_id: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Check the correlation record of a client-side container id (Iteration 21).

    A container id that the client observed is only worth anything when it is
    provably the container of **this** invocation. The correlation record
    therefore has to name

    * the function-call id the worker observed,
    * the application id of the run,
    * the container id itself,

    and the provider records the value was taken from. When the caller knows
    the function-call id or the application id of the run, the record has to
    name exactly that one.
    """
    if not isinstance(fact, dict) or fact.get("status") != OBSERVED:
        return True, None

    correlation = fact.get("correlation")
    if not isinstance(correlation, dict):
        return False, (
            "The client-observed container id carries no correlation record: a container id "
            "that is not tied to the function call of this run proves nothing"
        )

    value = fact.get("value")
    container_id = correlation.get("container_id")
    if container_id != value:
        return False, (
            f"The correlation record names the container id {container_id!r}, but the fact "
            f"carries {value!r}"
        )

    function_call_id = correlation.get("function_call_id")
    if not isinstance(function_call_id, str) or not MODAL_FUNCTION_CALL_ID_RE.fullmatch(
        function_call_id
    ):
        return False, (
            "The correlation record of the client-observed container id names no plausible "
            f"function-call id: {function_call_id!r}"
        )

    app_id = correlation.get("app_id")
    if not isinstance(app_id, str) or not MODAL_APP_ID_RE.fullmatch(app_id):
        return False, (
            "The correlation record of the client-observed container id names no plausible "
            f"application id: {app_id!r}"
        )

    if expected_function_call_id is not None and function_call_id != expected_function_call_id:
        return False, (
            f"The correlation record names the function call {function_call_id!r}, but this run "
            f"observed {expected_function_call_id!r}: the container id belongs to another "
            "invocation"
        )

    if expected_app_id is not None and app_id != expected_app_id:
        return False, (
            f"The correlation record names the application {app_id!r}, but this run belongs to "
            f"{expected_app_id!r}: the container id belongs to another application"
        )

    records = correlation.get("provider_records")
    if not isinstance(records, dict) or not records:
        return False, (
            "The correlation record of the client-observed container id carries no provider "
            "records: the provider's own answer is what makes the value trustworthy"
        )

    for record_name in ("call_graph_input", "app_container_listing", "task_record"):
        record = records.get(record_name)
        if not isinstance(record, dict):
            return False, (
                f"The correlation record of the client-observed container id carries no "
                f"provider record {record_name!r}"
            )

    listing = records.get("app_container_listing")
    if listing.get("container_id") != value or listing.get("app_id") != app_id:
        return False, (
            "The container listing of the correlation record does not name the very container "
            "and the very application of the fact"
        )

    task_record = records.get("task_record")
    if task_record.get("container_id") != value or task_record.get("app_id") != app_id:
        return False, (
            "The task record of the correlation record does not name the very container and "
            "the very application of the fact"
        )

    call_graph = records.get("call_graph_input")
    if call_graph.get("task_id") != value or call_graph.get("function_call_id") != function_call_id:
        return False, (
            "The call-graph record of the correlation record does not tie the very container "
            "to the very function call of the fact"
        )

    return True, None


def validate_client_observed_facts(
    block: Any,
    *,
    strict_sources: bool = False,
    expected_function_call_id: Optional[str] = None,
    expected_app_id: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validate the facts the **client** observed from the provider.

    Modal SDK 1.5.5 gives a function container neither a running-app accessor
    (``modal.running_app`` is a module, not a callable) nor any supported
    source of a provider-issued container id. The application id, the app page
    URL and the container id of a run are therefore facts of the client, and
    they live in their own block so that they can never be mistaken for worker
    observations.

    Rejects:

    * a block that is not an object;
    * a fact that does not declare the client side - a client observation that
      does not say where it was observed is exactly the ambiguity this block
      exists to remove;
    * a fact that declares the worker side;
    * an observed application id that is not a plausible Modal application id;
    * an observed app page URL that is not the provider's own dashboard URL of
      such an application;
    * a ``NOT_AVAILABLE`` fact without a reason;
    * (Iteration 21, ``strict_sources``) an observed value that does not name a
      **registered** observation source, or whose side contradicts the
      registered one;
    * (Iteration 21) an observed container id that carries no correlation
      record, or whose correlation record names another invocation, another
      application or another container;
    * (Iteration 22, ``strict_sources``) an observed value that names **no**
      observation side - the side is mandatory in the strict mode, and it has
      to be the registered one.
    """
    if block is None:
        return True, None
    if not isinstance(block, dict):
        return False, "The client-observed block is not an object"

    for field_name, fact in block.items():
        if not isinstance(fact, dict):
            return False, (
                f"The client-observed fact for '{field_name}' is not a typed fact"
            )
        status = fact.get("status")
        if status not in IDENTITY_FACT_STATUSES:
            return False, (
                f"The client-observed fact for '{field_name}' has the unknown status "
                f"{status!r}"
            )

        declared = fact.get("observed_by")
        if declared != OBSERVATION_SIDE_CLIENT:
            return False, (
                f"The client-observed fact for '{field_name}' declares the observation side "
                f"{declared!r}, not {OBSERVATION_SIDE_CLIENT!r}: a client observation that does "
                "not name the client side may not be presented as a worker observation"
            )

        if status == NOT_AVAILABLE:
            if fact.get("value") is not None:
                return False, (
                    f"The client-observed fact for '{field_name}' is NOT_AVAILABLE but holds a "
                    "value"
                )
            reason = fact.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                return False, (
                    f"The client-observed fact for '{field_name}' is NOT_AVAILABLE without an "
                    "explicit reason"
                )
            continue

        value = fact.get("value")
        if not isinstance(value, str) or not value.strip():
            return False, (
                f"The client-observed fact for '{field_name}' holds no usable value"
            )
        if field_name == "app_id" and not MODAL_APP_ID_RE.fullmatch(value):
            return False, (
                f"The client-observed application id is malformed: {value!r}"
            )
        if field_name == "app_page_url" and not MODAL_APP_PAGE_URL_RE.fullmatch(value):
            return False, (
                f"The client-observed app page URL is not the provider's dashboard URL of an "
                f"application: {value!r}"
            )

        if strict_sources:
            # Iteration 21: only a registered source backs a provider-issued
            # value. A free-form source string is not enough.
            # Iteration 22: the side is mandatory as well - an observed value
            # has to say which side observed it.
            ok, error = validate_provider_observation_source(
                field_name,
                fact,
                expected_side=OBSERVATION_SIDE_CLIENT,
                require_side=True,
            )
            if not ok:
                return False, error

    if strict_sources:
        # The container id of a run is only worth anything when it is provably
        # the container of this very invocation.
        ok, error = validate_client_container_correlation(
            block.get("container_id"),
            expected_function_call_id=expected_function_call_id,
            expected_app_id=expected_app_id,
        )
        if not ok:
            return False, error

    return True, None


def _stage_observed_value(
    stages: Dict[str, Any],
    stage_name: str,
    field_name: str,
) -> Optional[str]:
    """The observed value of one field of one stage - ``None`` when absent."""
    stage = stages.get(stage_name) if isinstance(stages, dict) else None
    if not isinstance(stage, dict):
        return None
    fact = stage.get(field_name)
    if not isinstance(fact, dict) or fact.get("status") != OBSERVED:
        return None
    value = fact.get("value")
    return str(value) if isinstance(value, str) and value else None


def _client_block_observed_value(block: Any, field_name: str) -> Optional[str]:
    """The observed value of one field of the client block - ``None`` when absent."""
    if not isinstance(block, dict):
        return None
    fact = block.get(field_name)
    if not isinstance(fact, dict) or fact.get("status") != OBSERVED:
        return None
    value = fact.get("value")
    return str(value) if isinstance(value, str) and value else None


def validate_run_level_application_id(
    fact: Any,
    *,
    strict: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Validate the **run-level** application id of an invocation.

    The run-level application id is the application id of the EVM sandbox stage
    of the very same invocation (``benchmarks/adapters.py`` writes
    ``"modal_app_id": _stage_facts("evm_sandbox")["app_id"]``). It is therefore
    either the ``NOT_AVAILABLE`` fact of that stage - the worker cannot read the
    application id - or an observed one.

    In the **strict** mode the run-level fact is a typed fact of the **same
    registry** as the stage facts, and the consumer may not let it contradict
    the stage copy of the same field:

    * an **observed** value has to name the **registered** side of the field
      (``client``) and the registered source, and its value has to have the
      provider's shape;
    * a **missing**, a ``null`` and an **unknown** side are rejected;
    * a **worker**-side claim is rejected - the registered source of
      ``app_id`` may only be observed from the client side;
    * a **legacy flat** value names no side at all and is rejected;
    * a run that records **no** application id at all is rejected;
    * an **absence claim** that carries a value is rejected - an absence claim
      states that the value could not be observed, and it may not state a
      value as well.

    The **contradiction with the stage copy** of the same field - the run-level
    fact is the application id of the EVM sandbox stage of the same invocation
    and the two are one fact in two places - is checked by
    ``validate_run_level_application_id_against_stage()``. It runs **after**
    this check, so that a claim with the wrong side is still refused by the
    side rule and not by the contradiction rule.

    A ``NOT_AVAILABLE`` fact is an **absence claim**, not an observation claim:
    it states that the value could not be observed, not that it was observed
    from a side. It is therefore not side-checked - the artifacts of Iteration
    21 carry exactly that shape and stay valid. The evidence reference of such
    a fact is checked by the caller.

    Without ``strict`` the fact is not restricted at all: that is the
    compatibility path that reads the artifacts of Iterations 14-20, in which
    the run-level application id is a flat, side-less value.
    """
    if not strict:
        return True, None

    if fact is None:
        return False, (
            "The run records no application id: in the strict mode the run-level "
            "application id has to be a typed fact that names the side that observed it"
        )

    if not isinstance(fact, dict):
        return False, (
            "The run records the application id as a legacy flat value: in the strict mode "
            "every fact has to name the side that observed it"
        )

    status = fact.get("status")
    if status not in IDENTITY_FACT_STATUSES:
        return False, (
            f"The run-level application id has the unknown status {status!r}"
        )

    if status == NOT_AVAILABLE:
        # An absence claim - the evidence reference is checked by the caller.
        # It may not hold a value: it states that the value could not be
        # observed.  ``value: null`` is not a value.
        if fact.get("value") is not None:
            return False, (
                "The run-level application id is NOT_AVAILABLE but holds a value"
            )
        return True, None

    registered = PROVIDER_OBSERVATION_SOURCES["app_id"]
    return validate_provider_observation_source(
        "app_id",
        fact,
        expected_side=registered["side"],
        require_side=True,
    )


def validate_run_level_application_id_against_stage(
    fact: Any,
    stage_app_id_fact: Any,
) -> Tuple[bool, Optional[str]]:
    """
    Check that the run-level application id does not contradict the stage copy.

    The run-level application id **is** the application id of the EVM sandbox
    stage of the same invocation - the producer writes the very same fact in
    both places (``benchmarks/adapters.py``). The two are therefore one fact in
    two places, and one artifact may not state two different application ids
    for one invocation.

    The rule is deliberately narrow and deliberately **one-directional**:

    * an **observed** run-level value has to be the **same** value the stage
      copy observed - the two copies of one fact may not disagree;
    * an **observed** run-level value next to a stage copy that says
      ``NOT_AVAILABLE`` is refused - the run claims an application id that the
      stage copy states it could not observe;
    * a ``NOT_AVAILABLE`` run-level fact is **not** compared with the stage
      copy: an absence claim states that the value could not be observed, and
      the strict mode does not side-check an absence claim either. The stage
      copy may carry a **client-side** observation of the application id while
      the run-level copy states that the **worker** could not read it - the two
      statements are compatible, and the artifacts of Iteration 21 and the
      probes of Iteration 23 have exactly that shape;
    * a shape that is not a typed fact is left to the checks that own it: the
      legacy flat value of the stage is refused by the strict loop over the
      stages, and a missing stage is not a contradiction - the stages are not
      mandatory.

    This check belongs to the strict mode only: the compatibility path reads
    the artifacts of Iterations 14-20, whose run-level application id is a
    flat, side-less value.
    """
    if not isinstance(fact, dict) or not isinstance(stage_app_id_fact, dict):
        # Not two typed facts: there is nothing to compare, and the shape of
        # each of them is owned by another check.
        return True, None

    run_status = fact.get("status")
    stage_status = stage_app_id_fact.get("status")

    if run_status == OBSERVED and stage_status == OBSERVED:
        if fact.get("value") != stage_app_id_fact.get("value"):
            return False, (
                "The run-level application id contradicts the application id of the EVM "
                f"sandbox stage: the run states {fact.get('value')!r}, the stage states "
                f"{stage_app_id_fact.get('value')!r} - they are one fact in two places"
            )
        return True, None

    if run_status == OBSERVED and stage_status != OBSERVED:
        return False, (
            "The run-level application id contradicts the EVM sandbox stage: the run states "
            f"an observed application id ({fact.get('value')!r}) while the stage states "
            f"{stage_status!r}"
        )

    return True, None


def validate_modal_invocation_provenance(
    artifact: Dict[str, Any],
    *,
    known_app_ids: Optional[Iterable[str]] = None,
    evidence_root: Optional[os.PathLike | str] = None,
    strict_sources: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Validate the Modal invocation provenance of one target artifact.

    Rejects:
      * a missing or malformed provenance block;
      * a synthetic ``modal-app://`` style log URI;
      * a hardcoded-looking application id that is not a plausible Modal id;
      * an observed application id that is absent from the raw billing export;
      * a NOT_AVAILABLE fact without a reason;
      * a NOT_AVAILABLE fact without an evidence reference, or whose evidence
        reference does not verify against the referenced bytes (a reason string
        alone is never sufficient);
      * an observed function-call id that is not a plausible Modal id;
      * (Iteration 16) a stage that is backed by the evidence artifact of
        another stage, an artifact that declares a different stage, an absence
        whose kind disagrees with the stage's own evidence, and a missing field
        that blames the provider although the provider was never asked for it.

    ``evidence_root`` is the directory the evidence references are resolved
    against. Without it the referenced bytes cannot be verified and a
    NOT_AVAILABLE fact is therefore rejected.

    ``strict_sources`` applies the registry of the allowed observation sources
    and the correlation rule of the client-side container id (Iteration 21).
    The mode is opt-in and additive - the artifacts of Iterations 14-20 stay
    valid without it.

    In the strict mode the side of an observation is **mandatory**
    (Iteration 22): every observed identity fact of the client block and of
    every stage has to name the side that observed it, and that side has to be
    the one registered for the field. A missing, a ``null`` and an unknown side
    are rejected, and so is a side that contradicts the registered one. The
    legacy flat value of a stage names no side and is therefore rejected in the
    strict mode as well - it stays valid in the compatibility path, which is
    where the artifacts of Iterations 14-20 are read.

    The side of a **stage** fact is the side registered for its field
    (Iteration 23): a stage is not worker-side by construction, it records the
    observations of one stage and every observation names its own side. The
    worker-side rule of the runtime-identity envelope - a client observation
    may never be presented inside a worker envelope - stays a separate rule of
    :func:`validate_runtime_identity_envelope` and is not touched by this.
    """
    if has_synthetic_modal_uri(artifact):
        return False, "Modal provenance or artifact contains a synthetic log URI (modal-app://)"

    provenance = artifact.get("modal_invocation_provenance")
    if not isinstance(provenance, dict) or not provenance:
        return False, "Missing modal_invocation_provenance for the executed target"

    stages = provenance.get("stages")
    if not isinstance(stages, dict) or not stages:
        return False, "modal_invocation_provenance has no stages"

    # The facts the client observed from the provider live in their own block
    # (Iteration 20). They are checked separately from the worker-side stages:
    # a client observation may never be presented as a worker observation.
    client_block = provenance.get("client_observed")
    if strict_sources:
        # The container id of the client has to be the container of the very
        # invocation this provenance block describes.
        expected_call_id = _stage_observed_value(stages, "evm_sandbox", "function_call_id")
        expected_app = _client_block_observed_value(client_block, "app_id")
        ok, error = validate_client_observed_facts(
            client_block,
            strict_sources=True,
            expected_function_call_id=expected_call_id,
            expected_app_id=expected_app,
        )
    else:
        ok, error = validate_client_observed_facts(client_block)
    if not ok:
        return False, error

    known = set(known_app_ids or ())

    # The run-level application id is a fact of the same kind as the stage
    # facts: an unavailable one must carry verifiable evidence as well.
    run_app_fact = provenance.get("modal_app_id")
    if strict_sources:
        # The run-level fact is checked against the **registry** as well: it is
        # the application id of the EVM sandbox stage of this very invocation,
        # so the consumer may not let it contradict the stage copy of the same
        # field. A missing, a side-less and a wrong-side claim is refused -
        # the compatibility path (without ``strict_sources``) is untouched and
        # keeps reading the side-less artifacts of Iterations 14-20.
        ok, error = validate_run_level_application_id(run_app_fact, strict=True)
        if not ok:
            return False, error

        # The two copies are one fact in two places: the run-level application
        # id is the application id of the EVM sandbox stage of this very
        # invocation.  The **side** rule above keeps its precedence - a claim
        # with the wrong side is refused by the side rule and not by the
        # contradiction rule.
        evm_stage = stages.get("evm_sandbox") if isinstance(stages, dict) else None
        if isinstance(evm_stage, dict):
            ok, error = validate_run_level_application_id_against_stage(
                run_app_fact, evm_stage.get("app_id")
            )
            if not ok:
                return False, error

    if isinstance(run_app_fact, dict) and run_app_fact.get("status") == NOT_AVAILABLE:
        ok, error = require_verified_evidence_ref(
            run_app_fact,
            evidence_root=evidence_root,
            label="Modal provenance records 'modal_app_id' as NOT_AVAILABLE",
        )
        if not ok:
            return False, error

        # The run-level application id is the one the EVM sandbox stage
        # reported, so it may only be backed by that stage's evidence.
        evm_stage = stages.get("evm_sandbox") if isinstance(stages, dict) else None
        if isinstance(evm_stage, dict):
            evm_ref = evm_stage.get("evidence_ref")
            run_ref = run_app_fact.get("evidence_ref")
            if not (isinstance(evm_ref, dict) and evm_ref.get("path")):
                return False, (
                    "Modal provenance records 'modal_app_id' as NOT_AVAILABLE but the EVM "
                    "sandbox stage has no evidence of its own"
                )
            if not (isinstance(run_ref, dict) and run_ref.get("path")):
                return False, (
                    "Modal provenance records 'modal_app_id' as NOT_AVAILABLE without an "
                    "evidence reference"
                )
            if run_ref.get("path") != evm_ref.get("path"):
                return False, (
                    "Modal provenance records 'modal_app_id' as NOT_AVAILABLE but references the "
                    "evidence of another stage"
                )

    for stage_name, stage in stages.items():
        if not isinstance(stage, dict):
            return False, f"Modal provenance stage '{stage_name}' is not an object"

        for key in ("app_id", "function_call_id", "container_id"):
            if key not in stage:
                return False, f"Modal provenance stage '{stage_name}' is missing '{key}'"

        for key in ("app_id", "function_call_id", "container_id"):
            fact = stage[key]
            if isinstance(fact, dict):
                if fact.get("status") == NOT_AVAILABLE:
                    if not fact.get("reason"):
                        return False, (
                            f"Modal provenance stage '{stage_name}' records '{key}' as NOT_AVAILABLE "
                            "without an explicit reason"
                        )
                    ok, error = require_verified_evidence_ref(
                        fact,
                        evidence_root=evidence_root,
                        label=(
                            f"Modal provenance stage '{stage_name}' records '{key}' as "
                            "NOT_AVAILABLE"
                        ),
                    )
                    if not ok:
                        return False, error
                    continue
                if fact.get("status") != OBSERVED:
                    return False, (
                        f"Modal provenance stage '{stage_name}' has an unknown status for '{key}'"
                    )
                if not fact.get("source"):
                    return False, (
                        f"Modal provenance stage '{stage_name}' records '{key}' without an observation source"
                    )
                value = fact.get("value")
            else:
                # Legacy flat values are only acceptable when they are real ids.
                value = fact

            if value is None or value == NOT_AVAILABLE:
                if not (isinstance(stage[key], dict) and stage[key].get("reason")):
                    return False, (
                        f"Modal provenance stage '{stage_name}' has an unexplained missing '{key}'"
                    )
                continue

            if key == "app_id":
                if not isinstance(value, str) or not MODAL_APP_ID_RE.fullmatch(value):
                    return False, (
                        f"Modal provenance stage '{stage_name}' has a malformed application id: {value!r}"
                    )
                if known and value not in known:
                    return False, (
                        f"Modal provenance stage '{stage_name}' references application id {value!r} "
                        "which is absent from the raw billing export"
                    )
            elif key == "function_call_id":
                if not isinstance(value, str) or not MODAL_FUNCTION_CALL_ID_RE.fullmatch(value):
                    return False, (
                        f"Modal provenance stage '{stage_name}' has a malformed function-call id: {value!r}"
                    )
            elif key == "container_id":
                if not isinstance(value, str) or not MODAL_CONTAINER_ID_RE.fullmatch(value):
                    return False, (
                        f"Modal provenance stage '{stage_name}' has a malformed container id: {value!r}"
                    )
                if value in FORBIDDEN_SYNTHETIC_CONTAINER_IDS:
                    return False, (
                        f"Modal provenance stage '{stage_name}' uses the synthetic container id {value!r}"
                    )
                if SYNTHETIC_CONTAINER_ID_RE.fullmatch(value):
                    return False, (
                        f"Modal provenance stage '{stage_name}' uses the synthetic container id {value!r}; "
                        "the container identity must be the provider-issued worker id"
                    )

        if strict_sources:
            # Iteration 22: the stage facts are what a reader of the artifact
            # actually sees, so the side rule has to hold here as well. A fact
            # that names no side does not say who observed it - and the legacy
            # flat value names no side at all, which is exactly why it is not
            # acceptable in the strict mode. The compatibility path (without
            # ``strict_sources``) keeps reading the artifacts of Iterations
            # 14-20, which are exactly the ones with the flat shape.
            # Iteration 23: the side of a stage fact is the side **registered**
            # for its field - not a fixed 'worker'. A stage is not worker-side
            # by construction: it records the observations of one stage, and
            # every observation names its own side. The registry knows that
            # 'function_call_id' is observed by the worker and that 'app_id',
            # 'app_page_url' and 'container_id' are observed by the client, so
            # a correctly typed and correctly sided client-side fact in a stage
            # is accepted, while a worker-side claim on a client field is
            # still rejected as contradictory.
            for key, registered in PROVIDER_OBSERVATION_SOURCES.items():
                if key not in stage:
                    continue
                fact = stage[key]
                if not isinstance(fact, dict):
                    return False, (
                        f"Modal provenance stage '{stage_name}' records '{key}' as a legacy flat "
                        "value: in the strict mode every fact has to name the side that observed it"
                    )
                ok, error = validate_provider_observation_source(
                    key,
                    fact,
                    expected_side=registered["side"],
                    require_side=True,
                )
                if not ok:
                    return False, error

        for legacy_key in ("durable_log_ref", "provider_log_uri", "log_uri"):
            legacy = stage.get(legacy_key)
            if isinstance(legacy, str) and legacy.startswith("modal-app://"):
                return False, (
                    f"Modal provenance stage '{stage_name}' contains the synthetic log URI {legacy!r}"
                )

        # The stage must be backed by the evidence artifact of that very
        # stage: a digest-valid file of another stage proves nothing here.
        if evidence_root is not None:
            ok, error = validate_stage_evidence_binding(
                stage_name, stage, evidence_root=evidence_root
            )
            if not ok:
                return False, error

    # Cross-check the recorded application ids against the raw billing export.
    # A mismatch is rejected; an unavailable id is reported explicitly instead
    # of being skipped silently.
    if known:
        report = cross_check_app_ids(artifact, known)
        if report["status"] == "FAILED":
            return False, report["error"]

    return True, None


#: Status of a single App ID comparison between the invocation evidence and
#: the raw billing export.
APP_ID_MATCHED = "MATCHED"
APP_ID_MISMATCHED = "MISMATCHED"
APP_ID_NOT_COMPARED = "NOT_AVAILABLE_NOT_COMPARED"


def cross_check_app_ids(
    artifact: Dict[str, Any],
    billing_app_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    Cross-check the App IDs of the invocation evidence against the billing export.

    Every App ID the evidence records is compared with the App IDs the raw
    billing export contains. An App ID that was observed must be present in the
    export; an App ID that could not be observed is reported explicitly as
    ``NOT_AVAILABLE_NOT_COMPARED`` instead of being skipped silently.

    The returned report carries one comparison record per scope so that a
    skipped comparison is visible in the evidence.
    """
    provenance = artifact.get("modal_invocation_provenance")
    report: Dict[str, Any] = {
        "status": "PASSED",
        "error": None,
        "billing_app_ids_present": bool(billing_app_ids),
        "comparisons": [],
    }
    if not isinstance(provenance, dict):
        report["status"] = "NOT_APPLICABLE"
        report["error"] = "Missing modal_invocation_provenance"
        return report

    known = set(billing_app_ids or ())
    stages = provenance.get("stages")
    if not isinstance(stages, dict):
        stages = {}

    scopes: List[Tuple[str, Any]] = [("modal_app_id", provenance.get("modal_app_id"))]
    for stage_name, stage in stages.items():
        if isinstance(stage, dict):
            scopes.append((f"stages.{stage_name}.app_id", stage.get("app_id")))

    for scope, fact in scopes:
        record: Dict[str, Any] = {"scope": scope, "observed_app_id": None, "status": APP_ID_NOT_COMPARED}
        if isinstance(fact, dict):
            if fact.get("status") == OBSERVED:
                record["observed_app_id"] = fact.get("value")
            elif fact.get("status") == NOT_AVAILABLE:
                record["reason"] = fact.get("reason")
        elif isinstance(fact, str) and fact:
            # Legacy flat value: a real id is only acceptable when it looks
            # like one; the NOT_AVAILABLE marker is an explicit absence.
            if fact != NOT_AVAILABLE:
                record["observed_app_id"] = fact

        observed = record["observed_app_id"]
        if not observed:
            record["status"] = APP_ID_NOT_COMPARED
            record["reason"] = record.get(
                "reason", "the invocation evidence does not record an observed application id"
            )
        elif not known:
            record["status"] = APP_ID_NOT_COMPARED
            record["reason"] = "the raw billing export carries no application id to compare against"
        elif observed in known:
            record["status"] = APP_ID_MATCHED
        else:
            record["status"] = APP_ID_MISMATCHED
            record["reason"] = (
                f"application id {observed!r} is absent from the raw billing export"
            )

        report["comparisons"].append(record)
        if record["status"] == APP_ID_MISMATCHED:
            report["status"] = "FAILED"
            report["error"] = f"{scope}: {record['reason']}"

    return report


def validate_modal_app_id_consistency(
    artifact: Dict[str, Any],
    billing_app_ids: Optional[Iterable[str]] = None,
) -> Tuple[bool, Optional[str]]:
    """Validate the App ID cross-check between evidence and billing export."""
    report = cross_check_app_ids(artifact, billing_app_ids)
    if report["status"] == "FAILED":
        return False, report["error"]
    return True, None


def has_synthetic_modal_uri(payload: Any) -> bool:
    """True when the payload contains a fabricated ``modal-app://`` URI."""
    if isinstance(payload, str):
        return payload.startswith("modal-app://")
    if isinstance(payload, dict):
        for value in payload.values():
            if has_synthetic_modal_uri(value):
                return True
    if isinstance(payload, (list, tuple)):
        return any(has_synthetic_modal_uri(item) for item in payload)
    return False


# ---------------------------------------------------------------------------
# P0.1 - Billing attribution
# ---------------------------------------------------------------------------

#: Provider-issued correlation fields that may identify a single billing record.
#:
#: A target-level cost may only be derived from a billing record that carries one
#: of these identifiers **and** whose value occurs on exactly one raw line item.
#: Any other shape (a bare invocation id, an App id, an App/resource/interval
#: bucket) is not an exact correlation and is therefore never sufficient.
PROVIDER_JOIN_FIELDS = ("invocation_id", "function_call_id", "task_id")

#: Machine-readable reasons why a target could not be attributed to a billing
#: record. Every unattributed target carries one of these.
JOIN_REASON_NO_JOIN = "NO_JOIN_PROVIDED"
JOIN_REASON_MISSING_KEY = "MISSING_JOIN_KEY"
JOIN_REASON_MISSING_VALUE = "MISSING_JOIN_VALUE"
JOIN_REASON_UNSUPPORTED_FIELD = "UNSUPPORTED_PROVIDER_FIELD"
JOIN_REASON_BUCKET = "AGGREGATE_BUCKET_JOIN_REJECTED"
JOIN_REASON_NO_MATCH = "NO_MATCHING_LINE_ITEM"
JOIN_REASON_AMBIGUOUS = "AMBIGUOUS_MATCH"
JOIN_REASON_APP_MISMATCH = "APP_ID_MISMATCH"
JOIN_REASON_ALREADY_CLAIMED = "ALREADY_CLAIMED_BY_ANOTHER_TARGET"

#: Human-readable text for every machine-readable join reason code.
JOIN_REASON_TEXT: Dict[str, str] = {
    JOIN_REASON_NO_JOIN: (
        "no provider-backed invocation-level join was provided for this target; Modal billing "
        "exposes no target-level correlation"
    ),
    JOIN_REASON_MISSING_KEY: (
        "the join names no documented provider correlation field, so it identifies no billing "
        "record"
    ),
    JOIN_REASON_MISSING_VALUE: "the join names a provider correlation field but no value",
    JOIN_REASON_UNSUPPORTED_FIELD: (
        "the join names a field that is not a documented provider correlation identifier"
    ),
    JOIN_REASON_BUCKET: (
        "the join describes an App/resource/interval aggregate bucket; an aggregate is never "
        "allocated to an individual target"
    ),
    JOIN_REASON_NO_MATCH: (
        "the join value occurs on no raw billing line item, so the identifier is not backed by "
        "the billing record"
    ),
    JOIN_REASON_AMBIGUOUS: (
        "the join value occurs on more than one raw billing line item, so the correlation is not "
        "unique"
    ),
    JOIN_REASON_APP_MISMATCH: (
        "the matched billing record belongs to a different application than the join claims"
    ),
    JOIN_REASON_ALREADY_CLAIMED: (
        "the billing record is already attributed to another target, so the correlation is "
        "not unique"
    ),
}


@dataclass
class BillingLineItem:
    """A single raw billing line item as exported by the provider."""

    object_id: str
    resource: str
    cost_usd: float
    interval_start: str
    description: str = ""
    environment: str = ""
    index: int = -1
    provider_join_keys: Dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """
        Stable identity of the line item inside the raw export.

        The row index is part of the key so that two rows with identical
        content stay distinguishable. Without it a duplicated billing row
        would silently collapse into one and the join could not detect the
        ambiguity.
        """
        return (
            f"{self.index}|{self.object_id}|{self.resource}|{self.interval_start}"
            f"|{self.description}|{self.environment}"
        )

    @property
    def content_key(self) -> str:
        """Identity of the line item without the row index."""
        return f"{self.object_id}|{self.resource}|{self.interval_start}|{self.description}|{self.environment}"


def load_raw_billing_line_items(path: os.PathLike | str) -> List[BillingLineItem]:
    """
    Load the raw provider billing export into :class:`BillingLineItem` objects.

    Every row keeps its index in the export and every documented provider
    correlation field it carries. The provider keys are what makes an exact
    target-level join possible at all.
    """
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, list):
        raise ValueError("Raw billing export must be a list of line items")

    items: List[BillingLineItem] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        provider_keys = {
            field_name: str(entry[field_name])
            for field_name in PROVIDER_JOIN_FIELDS
            if entry.get(field_name) not in (None, "")
        }
        items.append(
            BillingLineItem(
                object_id=str(entry.get("object_id", "")),
                resource=str(entry.get("resource", "")),
                cost_usd=float(entry.get("cost", 0.0)),
                interval_start=str(entry.get("interval_start", "")),
                description=str(entry.get("description", "")),
                environment=str(entry.get("environment", "")),
                index=index,
                provider_join_keys=provider_keys,
            )
        )
    return items


@dataclass
class BillingAttribution:
    """
    Billing attribution split by level.

    ``app_session_level`` accounts for every raw line item exactly once.
    ``target_level`` holds one row per target; its cost stays ``None`` unless
    an *exact* provider-backed join to a single raw line item was proven.
    """

    app_session_level: List[Dict[str, Any]] = field(default_factory=list)
    target_level: List[Dict[str, Any]] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_cost_usd_exact: str = "0"
    attribution_policy: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app_session_level": self.app_session_level,
            "target_level": self.target_level,
            "total_cost_usd": self.total_cost_usd,
            "total_cost_usd_exact": self.total_cost_usd_exact,
            "attribution_policy": self.attribution_policy,
        }


def resolve_billing_join(
    join: Any,
    line_items: Sequence[BillingLineItem],
) -> Tuple[Optional[BillingLineItem], Optional[str]]:
    """
    Resolve one target-level join against the raw billing export.

    A join is only resolved when it carries a documented provider correlation
    field and a value that occurs on **exactly one** raw line item, and when
    that record belongs to the application the join claims.

    Everything else is rejected with a machine-readable reason code:

    ``MISSING_JOIN_KEY``
        the join names no provider correlation field;
    ``MISSING_JOIN_VALUE``
        the join names a field but no value;
    ``UNSUPPORTED_PROVIDER_FIELD``
        the join names a field that is not a documented provider identifier;
    ``AGGREGATE_BUCKET_JOIN_REJECTED``
        the join describes an App/resource/interval bucket, which is an
        aggregate and never identifies a single billing record;
    ``NO_MATCHING_LINE_ITEM``
        the join value occurs on no raw line item (a fabricated identifier);
    ``AMBIGUOUS_MATCH``
        the join value occurs on more than one raw line item (a duplicated
        billing row or a non-unique identifier);
    ``APP_ID_MISMATCH``
        the matched billing record belongs to a different application.
    """
    if not isinstance(join, dict) or not join:
        return None, JOIN_REASON_MISSING_KEY

    provider_field = join.get("provider_field")
    provider_value = join.get("provider_value")

    if provider_field in (None, ""):
        # A join that only names an App, a resource or an interval describes
        # an aggregate bucket. Such a bucket is never allocated to a target.
        bucket_keys = {"app_id", "resource", "interval_start", "line_item_key", "invocation_id"}
        if any(key in join for key in bucket_keys):
            return None, JOIN_REASON_BUCKET
        return None, JOIN_REASON_MISSING_KEY

    if provider_value in (None, ""):
        return None, JOIN_REASON_MISSING_VALUE

    if provider_field not in PROVIDER_JOIN_FIELDS:
        return None, JOIN_REASON_UNSUPPORTED_FIELD

    matches = [
        item
        for item in line_items
        if item.provider_join_keys.get(provider_field) == provider_value
    ]
    if not matches:
        return None, JOIN_REASON_NO_MATCH
    if len(matches) > 1:
        return None, JOIN_REASON_AMBIGUOUS

    matched = matches[0]
    claimed_app_id = join.get("app_id")
    if claimed_app_id not in (None, "") and matched.object_id != claimed_app_id:
        return None, JOIN_REASON_APP_MISMATCH

    return matched, None


def build_billing_attribution(
    line_items: Sequence[BillingLineItem],
    *,
    target_rows: Optional[Sequence[Dict[str, Any]]] = None,
    invocation_joins: Optional[Dict[str, Dict[str, Any]]] = None,
) -> BillingAttribution:
    """
    Build the billing attribution from the raw export.

    Each raw line item is assigned to exactly one app/session bucket. The
    target rows receive an app/session reference only; their cost stays
    ``None`` unless an *exact* provider-backed join to a single raw line item
    was proven. An App/resource/interval bucket is never allocated to an
    individual target, and no aggregate is ever prorated or duplicated.

    All aggregates are computed with :class:`decimal.Decimal` so that the
    reconciliation with the raw export is exact and not a floating-point
    approximation.
    """
    buckets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for item in line_items:
        bucket_key = (item.object_id, item.resource, item.interval_start)
        bucket = buckets.setdefault(
            bucket_key,
            {
                "app_id": item.object_id,
                "resource": item.resource,
                "interval_start": item.interval_start,
                "descriptions": [],
                "environments": [],
                "line_item_count": 0,
                "cost_usd": Decimal("0"),
                "line_item_keys": [],
            },
        )
        bucket["line_item_count"] += 1
        bucket["cost_usd"] += Decimal(str(item.cost_usd))
        bucket["line_item_keys"].append(item.key)
        if item.description and item.description not in bucket["descriptions"]:
            bucket["descriptions"].append(item.description)
        if item.environment and item.environment not in bucket["environments"]:
            bucket["environments"].append(item.environment)

    app_session_level: List[Dict[str, Any]] = []
    total = Decimal("0")
    for bucket_key in sorted(buckets):
        bucket = buckets[bucket_key]
        bucket["descriptions"].sort()
        bucket["environments"].sort()
        exact = bucket.pop("cost_usd")
        bucket["cost_usd"] = float(exact)
        bucket["cost_usd_exact"] = format(exact, "f")
        total += exact
        app_session_level.append(bucket)

    joins = invocation_joins or {}
    claimed: Dict[str, str] = {}
    target_level: List[Dict[str, Any]] = []
    for row in target_rows or []:
        target_id = str(row.get("target_id", ""))
        join = joins.get(target_id)
        cost: Optional[float] = None
        cost_exact: Optional[str] = None
        join_evidence: Optional[Dict[str, Any]] = None

        if join is None:
            cost_status = "UNATTRIBUTED_NO_INVOCATION_LEVEL_JOIN"
            reason_code: Optional[str] = JOIN_REASON_NO_JOIN
            reason = (
                "no provider-backed invocation-level join was provided for this target; "
                "Modal billing exposes no target-level correlation"
            )
        else:
            matched, failure = resolve_billing_join(join, line_items)
            if matched is None:
                cost_status = "UNATTRIBUTED_JOIN_NOT_PROVEN"
                reason_code = failure
                reason = JOIN_REASON_TEXT.get(failure or "", failure)
            elif matched.key in claimed:
                cost_status = "UNATTRIBUTED_JOIN_NOT_PROVEN"
                reason_code = JOIN_REASON_ALREADY_CLAIMED
                reason = (
                    f"the billing record {matched.key} is already attributed to target "
                    f"{claimed[matched.key]!r}"
                )
            else:
                exact = Decimal(str(matched.cost_usd))
                cost = float(exact)
                cost_exact = format(exact, "f")
                cost_status = "ATTRIBUTED"
                reason_code = None
                reason = None
                claimed[matched.key] = target_id
                join_evidence = {
                    "provider_field": join.get("provider_field"),
                    "provider_value": join.get("provider_value"),
                    "app_id": matched.object_id,
                    "line_item_key": matched.key,
                    "line_item_content_key": matched.content_key,
                    "resource": matched.resource,
                    "interval_start": matched.interval_start,
                    "cost_usd_exact": cost_exact,
                }

        target_level.append(
            {
                "target_id": target_id,
                "target_name": row.get("target_name"),
                "app_id": row.get("app_id"),
                "cost_usd": cost,
                "cost_usd_exact": cost_exact,
                "cost_status": cost_status,
                "cost_reason_code": reason_code,
                "cost_reason": reason,
                "invocation_join": join_evidence,
            }
        )

    return BillingAttribution(
        app_session_level=app_session_level,
        target_level=target_level,
        total_cost_usd=float(total),
        total_cost_usd_exact=format(total, "f"),
        attribution_policy={
            "status": "APP_SESSION_LEVEL_ONLY",
            "per_target_cost_usd": None,
            "policy_reason": (
                "Modal billing is reported at app-session and interval granularity. A target-level "
                "cost is assigned only when a documented provider correlation key resolves to "
                "exactly one raw billing line item of the claimed application; otherwise the "
                "target-level cost stays null and the reason is machine-readable."
            ),
            "provider_join_fields": list(PROVIDER_JOIN_FIELDS),
            "aggregate_bucket_allocation": "FORBIDDEN",
        },
    )


def validate_billing_attribution(
    attribution: Dict[str, Any],
    line_items: Sequence[BillingLineItem],
    *,
    known_app_ids: Optional[Iterable[str]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validate a billing attribution against the raw export.

    Checks that
      * every referenced application id exists in the raw export;
      * every raw line item is accounted for exactly once (no double counting,
        no silently dropped item);
      * the aggregates reconcile exactly with the raw export;
      * a target-level cost is only present when an exact, unique
        provider-backed join accompanies it, and that join resolves to the
        very same raw line item;
      * a raw line item is never attributed to more than one target;
      * an unattributed target carries a machine-readable reason code.
    """
    if not isinstance(attribution, dict):
        return False, "Billing attribution must be an object"

    app_level = attribution.get("app_session_level")
    target_level = attribution.get("target_level")
    if not isinstance(app_level, list):
        return False, "Billing attribution has no app_session_level rows"
    if not isinstance(target_level, list):
        return False, "Billing attribution has no target_level rows"

    known = set(known_app_ids or ())
    raw_keys = [item.key for item in line_items]
    raw_total = sum((Decimal(str(item.cost_usd)) for item in line_items), Decimal("0"))

    seen_keys: List[str] = []
    app_total = Decimal("0")
    for row in app_level:
        if not isinstance(row, dict):
            return False, "app_session_level contains a non-object row"
        app_id = row.get("app_id")
        if not isinstance(app_id, str) or not app_id:
            return False, "app_session_level row has no application id"
        if known and app_id not in known:
            return False, (
                f"Billing attribution references application id {app_id!r} which is absent from "
                "the raw billing export"
            )
        keys = row.get("line_item_keys")
        if not isinstance(keys, list) or not keys:
            return False, f"Billing attribution row for {app_id!r} references no raw line items"
        for key in keys:
            if key not in raw_keys:
                return False, f"Billing attribution row for {app_id!r} references unknown line item {key!r}"
            seen_keys.append(key)
        exact = row.get("cost_usd_exact")
        if exact is None:
            exact = str(row.get("cost_usd", "0"))
        try:
            app_total += Decimal(str(exact))
        except Exception:
            return False, f"Billing attribution row for {app_id!r} has a non-numeric cost"

    if len(seen_keys) != len(set(seen_keys)):
        return False, "Billing attribution double-counts at least one raw billing line item"

    missing = set(raw_keys) - set(seen_keys)
    if missing:
        return False, (
            f"Billing attribution omits {len(missing)} raw billing line item(s); every raw line "
            "item must be accounted for exactly once"
        )

    if app_total != raw_total:
        return False, (
            f"Billing attribution aggregate {app_total} does not reconcile exactly with the "
            f"raw export total {raw_total}"
        )

    declared_total = attribution.get("total_cost_usd")
    if declared_total is not None:
        declared_exact = attribution.get("total_cost_usd_exact")
        if declared_exact is None:
            declared_exact = str(declared_total)
        try:
            if Decimal(str(declared_exact)) != raw_total:
                return False, (
                    f"Billing attribution total {declared_exact} does not reconcile exactly with "
                    f"the raw export total {raw_total}"
                )
        except Exception:
            return False, "Billing attribution total_cost_usd is not a number"

    claimed_line_items: Dict[str, str] = {}
    for row in target_level:
        if not isinstance(row, dict):
            return False, "target_level contains a non-object row"
        target_id = row.get("target_id")
        cost = row.get("cost_usd")
        join = row.get("invocation_join")

        if cost is None:
            if not row.get("cost_reason_code"):
                return False, (
                    f"Target {target_id!r} has no target-level cost and no machine-readable "
                    "cost_reason_code"
                )
            continue

        if not isinstance(join, dict) or not join.get("provider_value"):
            return False, (
                f"Target {target_id!r} has a target-level cost without a proven "
                "invocation-level join"
            )

        resolved, failure = resolve_billing_join(
            {
                "provider_field": join.get("provider_field"),
                "provider_value": join.get("provider_value"),
                "app_id": join.get("app_id"),
            },
            line_items,
        )
        if resolved is None:
            return False, (
                f"Target {target_id!r} has a target-level cost without a proven invocation-level "
                f"join: {failure}"
            )

        if join.get("line_item_key") != resolved.key:
            return False, (
                f"Target {target_id!r} claims a target-level cost for a billing record that is "
                "not the one its join resolves to"
            )

        try:
            declared = Decimal(str(row.get("cost_usd_exact") or cost))
        except Exception:
            return False, f"Target {target_id!r} has a non-numeric target-level cost"
        if declared != Decimal(str(resolved.cost_usd)):
            return False, (
                f"Target {target_id!r} has a target-level cost that does not equal the cost of "
                "the joined billing record"
            )

        if resolved.key in claimed_line_items:
            return False, (
                f"Target {target_id!r} attributes the billing record {resolved.key} that is "
                f"already attributed to target {claimed_line_items[resolved.key]!r}"
            )
        claimed_line_items[resolved.key] = str(target_id)

    return True, None


# ---------------------------------------------------------------------------
# P0.2 - Replay integrity envelope
# ---------------------------------------------------------------------------

#: Keys every replay envelope must carry.
REPLAY_REQUIRED_KEYS = (
    "reproduced",
    "container_id",
    "command",
    "argv",
    "exit_code",
    "invariant_violated",
    "harness_verdict",
    "stdout_artifact",
    "stderr_artifact",
    "candidate_input_artifact",
    "harness_input_artifact",
    "utc_start_time",
    "utc_end_time",
)


@dataclass
class ReplayArtifact:
    """A stored replay artifact: exact bytes on disk plus their digests."""

    path: str
    byte_length: int
    sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "byte_length": self.byte_length, "sha256": self.sha256}


def persist_replay_artifact(
    directory: os.PathLike | str,
    name: str,
    content: bytes,
) -> ReplayArtifact:
    """
    Write replay bytes to disk exactly as given and describe them.

    The bytes are written verbatim (no newline translation, no re-encoding) so
    that the recorded digest always describes the file that is on disk.
    """
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / name
    with open(target_path, "wb") as handle:
        handle.write(content)
    return ReplayArtifact(
        path=name,
        byte_length=len(content),
        sha256=sha256_bytes(content),
    )


def validate_replay_evidence_envelope(
    artifact: Dict[str, Any],
    *,
    artifact_root: Optional[os.PathLike | str] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validate the independent replay evidence envelope (Iteration 14 P0.2).

    The validator is deliberately strict: a replay may only be CONFIRMED when
    the envelope is complete and every digest can be recomputed from the bytes
    that were actually stored.

    When ``artifact_root`` is given, the digests of the replay stdout, stderr,
    candidate input and harness input are recomputed from the stored files. A
    mismatch, a missing file or a reused initial-run digest is a hard failure.
    """
    replay_status = artifact.get("replay_status")
    replayed_breaches = artifact.get("replayed_breaches", 0)

    if replay_status != "CONFIRMED" and not replayed_breaches:
        return True, None

    tool_meta = artifact.get("tool_metadata", {}) if isinstance(artifact.get("tool_metadata"), dict) else {}
    replay_data = (
        artifact.get("replay_evidence")
        or tool_meta.get("replay_evidence")
        or tool_meta.get("replay_details")
    )
    if not isinstance(replay_data, dict) or not replay_data:
        return False, "Replay status is CONFIRMED but the replay evidence envelope is missing or empty"

    for key in REPLAY_REQUIRED_KEYS:
        if key not in replay_data:
            return False, f"Replay evidence envelope is missing required key '{key}'"

    # 1. Fresh container identity: must be a real observed container id.
    container_id = replay_data.get("container_id")
    if not isinstance(container_id, str) or not container_id:
        return False, "Replay evidence envelope has no container identity"
    if container_id in FORBIDDEN_SYNTHETIC_CONTAINER_IDS:
        return False, f"Replay evidence envelope uses the synthetic container id {container_id!r}"
    if SYNTHETIC_CONTAINER_ID_RE.fullmatch(container_id):
        return False, (
            f"Replay evidence envelope uses the synthetic container id {container_id!r}; the "
            "container identity must be the provider-issued worker id"
        )
    if not MODAL_CONTAINER_ID_RE.fullmatch(container_id):
        return False, f"Replay evidence envelope has a malformed container id {container_id!r}"

    # 2. Exact command / argv.
    cmd = replay_data.get("command")
    argv = replay_data.get("argv")
    if not isinstance(cmd, str) or not cmd:
        return False, "Replay evidence envelope has no exact command"
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        return False, "Replay evidence envelope has no exact argv list"

    # 3. Exit code must be 0 for a confirmed breach.
    exit_code = replay_data.get("exit_code", replay_data.get("return_code"))
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or exit_code != 0:
        return False, f"Replay exit_code must be the integer 0 for a confirmed breach, got {exit_code!r}"

    # 4. The trusted harness verdict must be an actual breach.
    if not replay_data.get("reproduced"):
        return False, "Replay evidence does not record a reproduction"
    if not replay_data.get("invariant_violated"):
        return False, "Replay evidence does not record an invariant violation"
    if replay_data.get("harness_verdict") != "BREACH":
        return False, (
            f"Replay evidence harness_verdict must be 'BREACH', got {replay_data.get('harness_verdict')!r}"
        )

    # 5. Timestamps must be replay-specific, not the initial run's timestamps.
    utc_start = replay_data.get("utc_start_time")
    utc_end = replay_data.get("utc_end_time")
    if not utc_start or not utc_end:
        return False, "Replay evidence envelope has no replay-specific timestamps"
    initial_start = artifact.get("utc_start_time")
    initial_end = artifact.get("utc_end_time")
    if initial_start and utc_start == initial_start:
        return False, "Replay evidence reuses the initial run's start timestamp"
    if initial_end and utc_end == initial_end:
        return False, "Replay evidence reuses the initial run's end timestamp"

    # 6. The stored replay artifacts must exist and their digests must match.
    if artifact_root is None:
        return False, (
            "Replay evidence envelope cannot be verified without the stored replay artifacts; "
            "no artifact root was provided"
        )

    root = Path(artifact_root)
    for key in ("stdout_artifact", "stderr_artifact", "candidate_input_artifact", "harness_input_artifact"):
        descriptor = replay_data.get(key)
        if not isinstance(descriptor, dict):
            return False, f"Replay evidence envelope has no '{key}' descriptor"
        rel_path = descriptor.get("path")
        declared_sha = descriptor.get("sha256")
        declared_len = descriptor.get("byte_length")
        if not isinstance(rel_path, str) or not rel_path:
            return False, f"Replay evidence '{key}' has no path"
        if not is_sha256(declared_sha):
            return False, f"Replay evidence '{key}' has no valid SHA-256 digest"
        if not isinstance(declared_len, int) or isinstance(declared_len, bool) or declared_len < 0:
            return False, f"Replay evidence '{key}' has no valid byte length"

        resolved = root / rel_path
        if not resolved.is_file():
            return False, f"Replay evidence '{key}' points at a missing artifact: {rel_path}"
        data = resolved.read_bytes()
        if len(data) != declared_len:
            return False, (
                f"Replay evidence '{key}' byte length {declared_len} does not match the stored "
                f"artifact ({len(data)} bytes)"
            )
        actual_sha = sha256_bytes(data)
        if actual_sha != declared_sha:
            return False, (
                f"Replay evidence '{key}' digest {declared_sha} does not match the recomputed "
                f"digest of the stored bytes ({actual_sha})"
            )

    # 7. The candidate/harness digests must describe the exact replay inputs.
    initial_candidate = artifact.get("output_sha256")
    if initial_candidate:
        replay_candidate = replay_data["candidate_input_artifact"]["sha256"]
        if replay_candidate != initial_candidate:
            return False, (
                "Replay candidate input digest does not match the candidate that was executed"
            )

    return True, None


# ---------------------------------------------------------------------------
# P0.3 - Remote EVM toolchain provenance
# ---------------------------------------------------------------------------

#: Facts every executed EVM stage must report.
REMOTE_EVM_REQUIRED_FACTS = (
    "remote_os",
    "remote_platform",
    "image_digest",
    "forge_version",
    "solc_versions",
    "exact_forge_argv",
    "working_directory",
    "compiler_settings",
)

#: Values that only ever appeared as hardcoded constants in the old adapter.
#: They are rejected so a stale constant cannot masquerade as an observation.
LEGACY_HARDCODED_EVM_FACTS = {
    "remote_os": "Debian GNU/Linux 12 (bookworm)",
    "image_tag": "debian:12-slim-foundry",
    "forge_version": "forge 1.9.5 (92f59f6 2026-11-04T00:23:44.821105000Z)",
    "working_directory": "/tmp/aegis_sandbox",
}

#: The observation source each remote EVM fact must come from.
#:
#: A fact is only an observation when the source names the command, file or
#: runtime value it was read from. This is what separates "the worker read
#: /etc/os-release" from "the client wrote a constant into the artifact".
EVM_FACT_REQUIRED_SOURCE_TOKENS = {
    "remote_os": ("os-release",),
    "remote_platform": ("os.name", "platform."),
    "image_digest": ("image_id",),
    "forge_version": ("forge --version",),
    "solc_versions": ("forge config",),
    "exact_forge_argv": ("argv",),
    "working_directory": ("cwd",),
    "compiler_settings": ("forge config",),
}

#: Legacy constants whose value coincides with a genuine observation and must
#: therefore not be rejected on the value alone (the source carries the proof).
EVM_FACTS_WITH_COINCIDENT_LEGACY_VALUE = ("remote_os", "remote_platform")

#: The shape of a genuine `forge --version` output.
FORGE_VERSION_RE = re.compile(r"forge\s+Version:\s*\d+\.\d+\.\d+")

#: The shape of a solc version string.
SOLC_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+")


def validate_remote_evm_toolchain_provenance(
    artifact: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """
    Validate the remote EVM toolchain provenance of one target artifact.

    The provenance must consist of observed facts only. A missing fact must be
    an explicit NOT_AVAILABLE with a reason; a target whose EVM stage did not
    run must carry no EVM provenance at all.
    """
    evm_outcome = artifact.get("evm_outcome")
    sec_verdict = artifact.get("security_verdict")
    process_exit_code = artifact.get("process_exit_code")

    tool_meta = artifact.get("tool_metadata", {}) if isinstance(artifact.get("tool_metadata"), dict) else {}
    provenance = artifact.get("remote_evm_provenance") or tool_meta.get("remote_evm_provenance")

    evm_not_run = (
        evm_outcome == "NOT_RUN"
        or (sec_verdict == "GENERATION_FORMAT_ERROR" and process_exit_code == -4)
    )
    if evm_not_run:
        if provenance is not None:
            return False, (
                "Target did not execute an EVM stage but carries remote_evm_provenance; "
                "provenance must never be copied onto a target that did not run EVM"
            )
        return True, None

    if not isinstance(provenance, dict) or not provenance:
        return False, "Missing remote_evm_provenance dictionary for the executed EVM stage"

    for fact_name in REMOTE_EVM_REQUIRED_FACTS:
        if fact_name not in provenance:
            return False, f"Missing remote EVM provenance fact: '{fact_name}'"

        fact = provenance[fact_name]
        if isinstance(fact, dict):
            status = fact.get("status")
            if status == NOT_AVAILABLE:
                if not fact.get("reason"):
                    return False, (
                        f"Remote EVM provenance fact '{fact_name}' is NOT_AVAILABLE without a reason"
                    )
                continue
            if status != OBSERVED:
                return False, f"Remote EVM provenance fact '{fact_name}' has an unknown status"
            if not fact.get("source"):
                return False, (
                    f"Remote EVM provenance fact '{fact_name}' is observed without an observation source"
                )
            source = str(fact.get("source"))
            required_tokens = EVM_FACT_REQUIRED_SOURCE_TOKENS.get(fact_name)
            if required_tokens and not any(token in source for token in required_tokens):
                return False, (
                    f"Remote EVM provenance fact '{fact_name}' was not observed from the expected "
                    f"source (expected one of {list(required_tokens)}, got {source!r})"
                )
            value = fact.get("value")
        else:
            value = fact

        if value is None or (isinstance(value, (str, list, dict)) and len(value) == 0):
            return False, f"Remote EVM provenance fact '{fact_name}' is empty"

        legacy = LEGACY_HARDCODED_EVM_FACTS.get(fact_name)
        if (
            legacy is not None
            and value == legacy
            and fact_name not in EVM_FACTS_WITH_COINCIDENT_LEGACY_VALUE
        ):
            return False, (
                f"Remote EVM provenance fact '{fact_name}' equals the legacy hardcoded constant "
                f"{legacy!r}; provenance must be observed, not templated"
            )

    # The image identity must be an immutable digest, never a mutable tag.
    image_digest = provenance["image_digest"]
    image_value = fact_value(image_digest)
    if image_value is not None:
        if not isinstance(image_value, str) or not MODAL_IMAGE_ID_RE.fullmatch(image_value):
            return False, (
                f"Remote EVM provenance image_digest {image_value!r} is not an immutable Modal image id"
            )

    # The recorded argv must be a real command line.
    argv = fact_value(provenance["exact_forge_argv"])
    if argv is not None:
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
            return False, "Remote EVM provenance exact_forge_argv is not a valid argv list"
        if Path(argv[0]).name != "forge":
            return False, (
                f"Remote EVM provenance exact_forge_argv does not start with the forge executable: "
                f"{argv[0]!r}"
            )

    # The Foundry version must look like real `forge --version` output.
    forge_version = fact_value(provenance["forge_version"])
    if forge_version is not None:
        if not isinstance(forge_version, str) or not FORGE_VERSION_RE.search(forge_version):
            return False, (
                "Remote EVM provenance forge_version does not look like the output of "
                f"`forge --version`: {forge_version!r}"
            )

    # The solc versions must look like real version strings.
    solc_versions = fact_value(provenance["solc_versions"])
    if solc_versions is not None:
        if not isinstance(solc_versions, list) or not solc_versions:
            return False, "Remote EVM provenance solc_versions is not a non-empty list"
        for version in solc_versions:
            if not isinstance(version, str) or not SOLC_VERSION_RE.match(version):
                return False, (
                    f"Remote EVM provenance solc_versions contains an implausible version: {version!r}"
                )

    # The working directory must be an absolute path.
    working_directory = fact_value(provenance["working_directory"])
    if working_directory is not None:
        if not isinstance(working_directory, str) or not os.path.isabs(working_directory):
            return False, (
                "Remote EVM provenance working_directory is not an absolute path: "
                f"{working_directory!r}"
            )

    # The effective compiler settings must be a mapping.
    compiler_settings = fact_value(provenance["compiler_settings"])
    if compiler_settings is not None:
        if not isinstance(compiler_settings, dict) or not compiler_settings:
            return False, "Remote EVM provenance compiler_settings is not a non-empty mapping"

    # The recorded exit code must agree with the execution record.
    observed_exit = fact_value(provenance.get("observed_exit_code")) if isinstance(
        provenance.get("observed_exit_code"), dict
    ) else provenance.get("observed_exit_code")
    if observed_exit is not None and process_exit_code is not None:
        if int(observed_exit) != int(process_exit_code):
            return False, (
                f"Remote EVM provenance exit code {observed_exit} disagrees with the recorded "
                f"process exit code {process_exit_code}"
            )

    return True, None


# ---------------------------------------------------------------------------
# P0.4 - Safe-control sentinel
# ---------------------------------------------------------------------------

#: The exact sentinel emitted by every repository-owned harness.
#: Keyed by target name; the value is the complete revert reason.
#: The registry mirrors the immutable ``benchmarks/targets/solidity/*Harness.t.sol``
#: sources and is verified against them by the test suite.
HARNESS_SENTINELS: Dict[str, str] = {
    "AccessControlVault": "EXPLOIT_FAILED: Owner uncompromised and treasury intact",
    "AuctionDoS": "EXPLOIT_FAILED: Auction liveness maintained",
    "CrossContractBridge": "EXPLOIT_FAILED: Bridge ledger synchronized",
    "ERC4626Vault": "EXPLOIT_FAILED: Honest depositor received fair proportional shares",
    "FeeShareYieldVault": "EXPLOIT_FAILED: Yield fees protected",
    "FlashLoanRewardPool": "EXPLOIT_FAILED: Reward pool protected against flash loan distortion",
    "LendingLiquidation": "EXPLOIT_FAILED: Collateral accounting preserved",
    "OracleLendingPool": "EXPLOIT_FAILED: Pool liquidity remains protected",
    "PrecisionStakingPool": "EXPLOIT_FAILED: Precision fee calculations preserved",
    "RewardDistributorLogic": "EXPLOIT_FAILED: Accounting consistency upheld",
    "SecureAccessControlVault": "EXPLOIT_FAILED: Safe control held. Owner and treasury intact.",
    "SecureERC4626Vault": "EXPLOIT_FAILED: Safe control held. Virtual offset mitigated inflation.",
    "SecureOraclePool": "EXPLOIT_FAILED: Safe control held. TWAP prevented oracle manipulation.",
    "SecureVault": "EXPLOIT_FAILED: Safe control held. Solvency intact.",
    "SignatureReplayWallet": "EXPLOIT_FAILED: Signature replay prevented",
    "Vault": "EXPLOIT_FAILED: Vault remains solvent, victim funds are secure",
}

#: The synthetic safe controls: targets that must never show a breach.
SAFE_CONTROL_TARGETS = frozenset(
    name for name in HARNESS_SENTINELS if name.startswith("Secure")
)

#: The exact sentinel of each of the four synthetic safe controls.
SAFE_CONTROL_SENTINELS: Dict[str, str] = {
    name: HARNESS_SENTINELS[name] for name in sorted(SAFE_CONTROL_TARGETS)
}

#: Failure reasons that must never be classified as a safe control.
_INFRA_FAILURE_MARKERS = (
    "INFRA_ERROR",
    "Compiler run failed",
    "ParserError",
    "Security Violation",
    "GENERATION_FORMAT_ERROR",
)


def validate_safe_control_sentinel_semantics(
    revert_reason: Optional[str],
    harness_verdict: Optional[str] = None,
    target_name: Optional[str] = None,
    *,
    harness_suite: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Validate safe-control sentinel semantics (Iteration 14 P0.4).

    A safe control is only proven when the revert reason is *exactly* the
    documented sentinel of the repository-owned harness for the given target.
    Arbitrary prefixes, suffixes and near-matches are rejected, as are generic
    reverts, panic codes, compilation errors, malformed output and
    infrastructure failures.
    """
    if not revert_reason or not isinstance(revert_reason, str) or not revert_reason.strip():
        return False, "MISSING_REVERT_REASON"

    reason = revert_reason.strip()

    # Compilation failures are never a safe control.
    if "Compiler run failed" in reason:
        return False, "COMPILATION_ERROR_NOT_SENTINEL"

    # Generic EVM failure shapes are never a safe control.
    if "EvmError: Revert" in reason:
        return False, "GENERIC_EVM_REVERT_NOT_SENTINEL"
    if "Panic" in reason:
        return False, "EVM_PANIC_NOT_SENTINEL"

    # Infrastructure failures are never a safe control.
    for marker in _INFRA_FAILURE_MARKERS:
        if marker in reason:
            return False, f"INFRASTRUCTURE_FAILURE_NOT_SENTINEL: {reason}"

    # A safe control is only meaningful for a documented harness target.
    if target_name is None:
        return False, "MISSING_TARGET_CONTEXT_FOR_SENTINEL"

    expected = HARNESS_SENTINELS.get(target_name)
    if expected is None:
        return False, f"TARGET_IS_NOT_A_DOCUMENTED_HARNESS_TARGET: {target_name}"

    # The harness context must match the target when it is supplied.
    if harness_suite is not None:
        expected_suite = f"test/{target_name}Harness.t.sol"
        if harness_suite != expected_suite:
            return False, (
                f"HARNESS_CONTEXT_MISMATCH: expected {expected_suite!r} for {target_name!r}, "
                f"got {harness_suite!r}"
            )

    if harness_verdict is not None and harness_verdict != "NO_BREACH":
        return False, f"HARNESS_VERDICT_NOT_NO_BREACH: {harness_verdict}"

    if reason == expected:
        return True, "SAFE_RUN"

    # The exact sentinel of a different target is still a context mismatch.
    owner = next(
        (name for name, sentinel in HARNESS_SENTINELS.items() if sentinel == reason),
        None,
    )
    if owner is not None:
        return False, f"SENTINEL_BELONGS_TO_OTHER_TARGET: {owner}"

    if reason.startswith(expected):
        return False, f"SENTINEL_SUFFIX_MISMATCH: {reason}"
    if expected.startswith(reason):
        return False, f"SENTINEL_PREFIX_MISMATCH: {reason}"
    return False, f"UNRECOGNIZED_REVERT_REASON: {reason}"
