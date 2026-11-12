"""The approval of a step and its verification.

**Why this module exists.** The dispatch gate of ``benchmarks/r1_dispatch.py``
is a *mechanism*: it enforces the invocation budget, the concurrency gate, the
ceiling assertion, the declared bounds, the egress declaration, the payload cap
and the read-only autoscaler read-back. A mechanism is not an authorisation.
Before this module existed, the gate accepted a :class:`~benchmarks.r1_dispatch.StepPolicy`
that any caller could construct in-process - including its ``approved_by``
field - so the gate authorised itself. The R1 re-review named that as a P0.

**The approval is a signed artifact.** An approval is a JSON artifact that

* names the step, the approver, the moment of the approval, the call sites it
  covers and the exact policy it approves;
* signs the canonical digest of the complete effective D26-D29 dispatch
  envelope (resource/lifecycle/autoscaler profiles, network policies,
  persistence limits, model/cache identity and cost-input digests), and
* carries an **RSA signature** (RSASSA-PKCS1-v1_5 over SHA-256) over the
  canonical form of that payload.

**The artifact carries no authority.** :class:`ApprovalArtifact` is data: the
payload and the signature. The authority is the *signature*, and the only
thing that turns a signature into an authorisation is the verification against
the **public** key of the approval authority, which the repository pins in
:data:`PINNED_PUBLIC_KEY` (mirrored for the audit trail in
``benchmarks/evidence/r1_approval_key.json``). The private half of that key
never enters this repository and never enters the process: a caller that can
only run code here cannot mint an approval.

**The gate verifies the artifact itself.** The dispatch gate does not accept a
"verified approval" object: it accepts the **signed artifact** and verifies the
signature itself, at dispatch time, against the pinned key
(``benchmarks.r1_dispatch.DispatchGate._check_approval``). There is therefore
no value whose *construction* conveys authority - the previous design had one
(a module-global issuance token that any caller could read and hand to the
constructor; the R1 re-review forged an approval with it, and the token is
gone).

**R1 pins no key.** The pinned key is ``None``, because no step of the
evidence-regeneration workflow has been approved by the maintainer yet. The
consequence is the intended one: **no provider dispatch is possible in R1**,
and it is impossible *structurally* - not only because the bounds of the
container classes are required-but-unset. A caller that constructs a policy
in-process, supplies permissive profile and read-back doubles and reaches a
provider double is refused with ``approval_not_verified``.

**The threat model.** This module protects against a caller *inside this
process* that reaches the workflow through its own API, its registries and its
guards. It does not protect against an adversary who can execute arbitrary code
in the same process: such an adversary can patch the verifier, the pinned key or
the gate itself. That is a property of the language, not of this module; the
guarantee it makes is the auditable one - *the repository contains no signing
key, so the repository cannot authorise a provider dispatch on its own*, and
*no approval can be minted without the signature of the approval authority*.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

#: The signature algorithm of an approval artifact.
ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"

#: The file that mirrors the pinned public key of the approval authority.
PINNED_KEY_PATH = (
    Path(__file__).resolve().parent.parent
    / "benchmarks"
    / "evidence"
    / "r1_approval_key.json"
)

#: The **pinned public key** of the approval authority - ``(modulus, exponent)``.
#:
#: The pin lives in the **source** and not in a file that is read at runtime: a
#: caller that can write a file into the working tree must not be able to
#: install a key of its own. The evidence file mirrors the pin for the audit
#: trail, and a mirror that does not match this constant is refused (fail
#: closed) - see :func:`pinned_public_key`.
#:
#: ``None`` means: the repository pins no key. That is the state of R1 - no
#: step of the workflow is approved, so no approval can be verified and no
#: provider dispatch can be authorised.
PINNED_PUBLIC_KEY: Optional[Tuple[int, int]] = None

#: The DER prefix of a SHA-256 ``DigestInfo`` (RFC 8017, section 9.2).
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class ApprovalNotVerified(RuntimeError):
    """Raised when an approval artifact is absent, malformed or not signed."""


@dataclass(frozen=True)
class ApprovalArtifact:
    """The signed approval artifact: the payload and its signature.

    The artifact is **data and carries no authority**. It can be constructed by
    anyone - a forged artifact is refused by the verification, not by the
    constructor. The authority is the signature, and only the verification
    against the pinned public key of the approval authority produces it.
    """

    payload: Mapping[str, Any]
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping):
            raise ApprovalNotVerified("the approval payload is not a mapping")
        if not isinstance(self.signature, (bytes, bytearray)):
            raise ApprovalNotVerified("the approval signature is not a byte string")
        object.__setattr__(self, "signature", bytes(self.signature))

    @property
    def digest(self) -> str:
        """The digest of the payload of this artifact."""
        return payload_digest(self.payload)


@dataclass(frozen=True)
class VerifiedApproval:
    """The **verified claims** of an approval artifact.

    The instance is the *result* of a successful verification
    (:func:`verify_approval`): the claims of the payload that the signature
    covers. It is **not an authorisation** - the dispatch gate never accepts
    one, it verifies the signed artifact itself. A caller that constructs this
    class by hand authorises nothing.
    """

    step_id: str
    approved_by: str
    approved_at: str
    call_sites: Tuple[str, ...]
    policy_digest: str
    dispatch_envelope_digest: str
    artifact_digest: str

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


def public_key_record(key: Tuple[int, int]) -> Dict[str, Any]:
    """The record of a public key in the format of the evidence mirror."""
    modulus, exponent = key
    key_size = (modulus.bit_length() + 7) // 8
    return {
        "n": base64.b64encode(modulus.to_bytes(key_size, "big")).decode("ascii"),
        "e": int(exponent),
    }


def _mirror_matches(key: Tuple[int, int]) -> bool:
    """True when the evidence mirror carries exactly this key.

    The mirror is a second, human-readable copy of the pin. A mirror that is
    missing, unreadable, malformed or different from the source pin is a
    tamper of the pin - and a tampered pin is refused (fail closed).
    """
    try:
        raw = json.loads(PINNED_KEY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(raw, Mapping):
        return False
    recorded = raw.get("public_key")
    if not isinstance(recorded, Mapping):
        return False
    try:
        if int(recorded["e"]) != int(key[1]):
            return False
        if _decode_modulus(str(recorded["n"])) != int(key[0]):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    return True


def pinned_public_key() -> Optional[Tuple[int, int]]:
    """The pinned public key of the approval authority - or ``None``.

    The pin is :data:`PINNED_PUBLIC_KEY` - a constant of this module, not a
    file that is read at runtime. The evidence file mirrors it; when the two
    disagree the pin is refused.

    ``None`` means that the repository pins no key: no approval can be
    verified, and therefore no provider dispatch can be authorised. That is the
    state of R1.
    """
    key = PINNED_PUBLIC_KEY
    if key is None:
        return None
    if not _mirror_matches(key):
        return None
    return key


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
    """Verify an approval artifact and return its verified claims.

    The artifact is refused - never partially accepted - when the repository
    pins no key, when the signature does not match the payload, or when the
    payload does not name a step, an approver and the call sites it covers.

    **The result is claims, not an authorisation.** The dispatch gate verifies
    the signed artifact itself, at dispatch time; a caller that constructs a
    :class:`VerifiedApproval` by hand authorises nothing, because the gate
    never accepts one.
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
    dispatch_envelope = payload.get("dispatch_envelope")
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
    if not isinstance(dispatch_envelope, Mapping):
        raise ApprovalNotVerified("the approval does not bind a complete dispatch envelope")
    if dispatch_envelope.get("schema") != "r1-dispatch-envelope/1":
        raise ApprovalNotVerified("the dispatch envelope schema is missing or unsupported")

    return VerifiedApproval(
        step_id=step_id,
        approved_by=approved_by,
        approved_at=approved_at,
        call_sites=tuple(call_sites),
        policy_digest=policy_digest(policy),
        dispatch_envelope_digest=payload_digest(dispatch_envelope),
        artifact_digest=payload_digest(payload),
    )


def verify_artifact(artifact: ApprovalArtifact) -> VerifiedApproval:
    """Verify a signed artifact and return its verified claims."""
    if not isinstance(artifact, ApprovalArtifact):
        raise ApprovalNotVerified(
            f"the approval is a {type(artifact).__name__}, not a signed artifact"
        )
    return verify_approval(artifact.payload, artifact.signature)


def load_approval_artifact(path: Any) -> ApprovalArtifact:
    """Read the signed approval artifact of a file - the artifact, unverified.

    The artifact is the payload of the approval plus its signature:

    .. code-block:: json

        {
            "step_id": "R3",
            "approved_by": "maintainer",
            "approved_at": "2026-11-12",
            "call_sites": ["verify_exploit_remote"],
            "policy": { "...": "the approved step policy" },
            "dispatch_envelope": { "...": "the complete D26-D29 effective configuration" },
            "signature": "<base64 of the RSA signature>"
        }

    The artifact is **not** verified here: the gate verifies it, at dispatch
    time, against the pinned key.
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
    return ApprovalArtifact(payload=artifact, signature=raw_signature)


__all__ = [
    "ALGORITHM",
    "ApprovalArtifact",
    "ApprovalNotVerified",
    "PINNED_KEY_PATH",
    "PINNED_PUBLIC_KEY",
    "VerifiedApproval",
    "canonical_bytes",
    "load_approval_artifact",
    "payload_digest",
    "pinned_public_key",
    "policy_digest",
    "public_key_record",
    "sha256_hex",
    "verify_approval",
    "verify_artifact",
    "verify_signature",
]
