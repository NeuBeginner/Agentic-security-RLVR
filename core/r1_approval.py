"""The approval of a step and its verification.

**Why this module exists.** The dispatch gate of ``benchmarks/r1_dispatch.py``
is a *mechanism*: it enforces the invocation budget, the concurrency gate, the
ceiling assertion, the declared bounds, the egress declaration, the payload cap
and the read-only autoscaler read-back. A mechanism is not an authorisation.
Before this module existed, the gate accepted a :class:`~benchmarks.r1_dispatch.StepPolicy`
that any caller could construct in-process - including its ``approved_by``
field - so the gate authorised itself. The R1 re-review named that as a P0.

**The approval is external.** An approval is a JSON artifact that

* names the step, the approver, the moment of the approval, the call sites it
  covers and the exact policy it approves, and
* carries an **RSA signature** (RSASSA-PKCS1-v1_5 over SHA-256) over the
  canonical form of that payload.

The signature is verified against the **public** key of the approval authority,
which the repository pins in ``benchmarks/evidence/r1_approval_key.json``. The
private half of that key never enters this repository and never enters the
process: a caller that can only run code here cannot mint an approval.

**R1 pins no key.** The pinned file carries ``null``, because no step of the
evidence-regeneration workflow has been approved by the maintainer yet. The
consequence is the intended one: **no provider dispatch is possible in R1**,
and it is impossible *structurally* - not only because the bounds of the
container classes are required-but-unset. A caller that constructs a policy in
-process, supplies permissive profile and read-back doubles and reaches a
provider double is refused with ``approval_not_verified``.

**The threat model.** This module protects against a caller *inside this
process* that reaches the workflow through its own API, its registries and its
guards. It does not protect against an adversary who can execute arbitrary code
in the same process: such an adversary can patch the verifier, the pinned key or
the gate itself. That is a property of the language, not of this module; the
guarantee it makes is the auditable one - *the repository contains no approval
and no signing key, so the repository cannot authorise a provider dispatch on
its own*.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

#: The signature algorithm of an approval artifact.
ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"

#: The file that pins the public key of the approval authority.
PINNED_KEY_PATH = (
    Path(__file__).resolve().parent.parent
    / "benchmarks"
    / "evidence"
    / "r1_approval_key.json"
)

#: The DER prefix of a SHA-256 ``DigestInfo`` (RFC 8017, section 9.2).
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class ApprovalNotVerified(RuntimeError):
    """Raised when an approval artifact is absent, malformed or not signed."""


#: The token that marks an approval as *verified*. Only :func:`verify_approval`
#: hands it out, so a verified approval cannot be conjured by a caller that
#: merely knows the class.
_ISSUANCE = object()


@dataclass(frozen=True)
class VerifiedApproval:
    """An approval that has been verified against the pinned public key.

    The instance is produced by :func:`verify_approval` only: the constructor
    refuses an approval that does not carry the issuance token, so a caller
    cannot build one by hand.
    """

    step_id: str
    approved_by: str
    approved_at: str
    call_sites: Tuple[str, ...]
    policy_digest: str
    artifact_digest: str
    _issued_by: Any = None

    def __post_init__(self) -> None:
        if self._issued_by is not _ISSUANCE:
            raise ApprovalNotVerified(
                "a verified approval is produced by verify_approval() only"
            )

    def covers(self, function_name: str) -> bool:
        """True when the approval names this call site."""
        return function_name in self.call_sites


# --------------------------------------------------------------------------------------
# the canonical form of an approval
# --------------------------------------------------------------------------------------


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """The canonical byte form of a payload - the bytes that are signed.

    The form is deterministic: the keys are sorted and the separators are
    fixed, so the same payload always produces the same bytes and therefore
    the same digest.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """The SHA-256 digest of the data, in hex."""
    return hashlib.sha256(data).hexdigest()


def payload_digest(payload: Mapping[str, Any]) -> str:
    """The digest of a payload - what an approval binds."""
    return sha256_hex(canonical_bytes(payload))


def policy_digest(policy_payload: Mapping[str, Any]) -> str:
    """The digest of an approved policy.

    The approval binds the **exact** policy it approves: a caller that swaps
    a cap, a budget or a ceiling after the approval was issued does not hold
    the approval any more.
    """
    return payload_digest(policy_payload)


# --------------------------------------------------------------------------------------
# the pinned public key
# --------------------------------------------------------------------------------------


def _decode_modulus(value: str) -> int:
    return int.from_bytes(base64.b64decode(value), "big")


def pinned_public_key() -> Optional[Tuple[int, int]]:
    """The pinned public key of the approval authority - or ``None``.

    ``None`` means that the repository pins no key: no approval can be
    verified, and therefore no provider dispatch can be authorised. That is the
    state of R1.
    """
    try:
        raw = json.loads(PINNED_KEY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    key = raw.get("public_key")
    if not isinstance(key, dict):
        return None
    try:
        modulus = _decode_modulus(str(key["n"]))
        exponent = int(key["e"])
    except (KeyError, TypeError, ValueError):
        return None
    if modulus <= 0 or exponent <= 1:
        return None
    return modulus, exponent


# --------------------------------------------------------------------------------------
# the verification
# --------------------------------------------------------------------------------------


def _digest_info(data: bytes) -> bytes:
    """The DER ``DigestInfo`` of the data (RFC 8017, section 9.2)."""
    return _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(data).digest()


def verify_signature(payload: bytes, signature: bytes, public_key: Tuple[int, int]) -> bool:
    """True when the signature is a valid RSASSA-PKCS1-v1_5 signature.

    The verification is the standard one: the signature is raised to the
    public exponent, and the result has to be the exact PKCS#1 v1.5 encoding
    of the SHA-256 digest of the payload.
    """
    modulus, exponent = public_key
    key_size = (modulus.bit_length() + 7) // 8
    if len(signature) != key_size:
        return False
    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus:
        return False
    encoded = pow(signature_int, exponent, modulus).to_bytes(key_size, "big")
    info = _digest_info(payload)
    padding_length = key_size - 3 - len(info)
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + info
    return encoded == expected


def verify_approval(payload: Mapping[str, Any], signature: bytes) -> VerifiedApproval:
    """Verify an approval artifact and return the verified approval.

    The artifact is refused - never partially accepted - when the repository
    pins no key, when the signature does not match the payload, or when the
    payload does not name a step, an approver and the call sites it covers.
    """
    key = pinned_public_key()
    if key is None:
        raise ApprovalNotVerified(
            "the repository pins no approval key: no approval can be verified, so "
            "no provider dispatch can be authorised"
        )
    if not isinstance(payload, Mapping):
        raise ApprovalNotVerified("the approval payload is not a mapping")
    if not isinstance(signature, (bytes, bytearray)):
        raise ApprovalNotVerified("the approval signature is not a byte string")
    if not verify_signature(canonical_bytes(payload), bytes(signature), key):
        raise ApprovalNotVerified(
            "the approval signature does not match the payload: the artifact is "
            "not signed by the approval authority"
        )

    step_id = payload.get("step_id")
    approved_by = payload.get("approved_by")
    approved_at = payload.get("approved_at")
    call_sites = payload.get("call_sites")
    policy = payload.get("policy")
    if not isinstance(step_id, str) or not step_id:
        raise ApprovalNotVerified("the approval names no step")
    if not isinstance(approved_by, str) or not approved_by:
        raise ApprovalNotVerified("the approval names no approver")
    if not isinstance(approved_at, str) or not approved_at:
        raise ApprovalNotVerified("the approval carries no moment of approval")
    if not isinstance(call_sites, (list, tuple)) or not call_sites:
        raise ApprovalNotVerified("the approval covers no call site")
    if not all(isinstance(name, str) and name for name in call_sites):
        raise ApprovalNotVerified("the approval names an invalid call site")
    if not isinstance(policy, Mapping):
        raise ApprovalNotVerified("the approval approves no policy")

    return VerifiedApproval(
        step_id=step_id,
        approved_by=approved_by,
        approved_at=approved_at,
        call_sites=tuple(call_sites),
        policy_digest=policy_digest(policy),
        artifact_digest=payload_digest(payload),
        _issued_by=_ISSUANCE,
    )


def load_approval(path: Any) -> VerifiedApproval:
    """Verify the approval artifact of a file and return the verified approval.

    The artifact is the payload of the approval plus its signature:

    .. code-block:: json

        {
            "step_id": "R3",
            "approved_by": "maintainer",
            "approved_at": "2026-11-12",
            "call_sites": ["verify_exploit_remote"],
            "policy": { "...": "the approved step policy" },
            "signature": "<base64 of the RSA signature>"
        }
    """
    try:
        artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ApprovalNotVerified(
            f"the approval artifact is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(artifact, dict):
        raise ApprovalNotVerified("the approval artifact is not a mapping")
    signature = artifact.pop("signature", None)
    if not isinstance(signature, str):
        raise ApprovalNotVerified("the approval artifact carries no signature")
    try:
        raw_signature = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError) as exc:
        raise ApprovalNotVerified(
            f"the approval signature is not valid base64: {exc}"
        ) from exc
    return verify_approval(artifact, raw_signature)


__all__ = [
    "ALGORITHM",
    "ApprovalNotVerified",
    "PINNED_KEY_PATH",
    "VerifiedApproval",
    "canonical_bytes",
    "load_approval",
    "payload_digest",
    "pinned_public_key",
    "policy_digest",
    "sha256_hex",
    "verify_approval",
    "verify_signature",
]
