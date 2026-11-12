"""The shared fixtures of the R1 test suites.

The approval fixture is the **out-of-band act of the approval authority**: the
artifact is signed with a test key and the test pins its public key for the
duration of the test. The key pair below is a *fixture* - the repository pins
no approval key (``core/r1_approval.PINNED_PUBLIC_KEY`` is ``None`` and
``benchmarks/evidence/r1_approval_key.json`` carries ``null``), so the test key
cannot authorise anything outside this test suite and the live provider
dispatch stays impossible in R1.

The fixture hands out the **signed artifact** - the payload and the signature -
and not a "verified approval" object: the dispatch gate verifies the artifact
itself, at dispatch time, so there is no value whose construction conveys
authority (the R1 re-review forged one through the module's issuance token).

Everything here is local: no test performs a provider call, a deployment, a
volume operation or a model download.
"""

from __future__ import annotations

import base64
from typing import Any, Callable, Dict, Iterable, Mapping, Optional

import pytest

from core import r1_bounds as r1

#: The public key of the test fixture - the repository pins none.
_TEST_MODULUS = (
    "zQ9XIV6++xRsHXBUcBlz6Y3lPYxGgQrbQVLakzcT1J8HS0bKNw/ZkQltiFJsglP1gnicjPAHFEVAV93X9Q"
    "ks4bp5UV6NLV0ooFUlmao4yDdTS1vOmSrjM5oFfmLxuRam4LOyEdvswGFpQYko9U1BHuByMFbHNtWiiSH8/C"
    "bs/b6fubrxQ11Sg/aKaPeMMjaMiF7x7rFglsd4vu0VssCgAtIrUzlfzLWmpDi5gOEg5GDJQhh7cDNpP9ZvL1Tj"
    "k+jfBfnpXcO9jV1mm6gsUFxB6rhfYd9YINjwz7YjJQhZDQSoHZ3B2um2lANnedoZykiyRNxW1cCIM/IxHH1u"
    "fWW6HQ=="
)

#: The private exponent of the test fixture - a test artifact, never in use
#: outside this suite.
_TEST_PRIVATE_EXPONENT = (
    "QunaE0QRCupvmy2gCBJuLgzE/NAM46fwwwCv3XEQEgYwwaIgc1ZDNx499Ul8Kg0OpJwJ7b2XechdRi7YfRe"
    "Y4zHPy7sQU3i+PI98XQfcTo0rK4CSSo3hpOGCIGtWGIEpRFKu7T/4IhDHYYDJ8j3a3aH88QQoLp8I0jnajUe"
    "Adw4LCaC2Z8hhrXdkqDiR/A1+W6ClP0xHX0wDTyK/aG9X9faBvR0VPa6vGZzcWuGgq5VluP+adROf1F36ZV"
    "yvlvusLpeyKeHBOijmQaJfbg8B0BwQuLg2WUHqZPQ+gHWqyKcaNynKaEu/qZsOfmbYXFJICYY476es+ok/j3"
    "Dqeqodew=="
)

_TEST_EXPONENT = 65537


def _int_from_base64(value: str) -> int:
    return int.from_bytes(base64.b64decode(value), "big")


def _public_key() -> tuple:
    return _int_from_base64(_TEST_MODULUS), _TEST_EXPONENT


def sign_payload(payload: bytes) -> bytes:
    """Sign the payload with the test key - the maintainer's act, simulated."""
    from core import r1_approval

    modulus = _int_from_base64(_TEST_MODULUS)
    private_exponent = _int_from_base64(_TEST_PRIVATE_EXPONENT)
    key_size = (modulus.bit_length() + 7) // 8
    info = r1_approval._digest_info(payload)
    encoded = (
        b"\x00\x01" + b"\xff" * (key_size - 3 - len(info)) + b"\x00" + info
    )
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, modulus)
    return signature.to_bytes(key_size, "big")


@pytest.fixture
def approval_authority(monkeypatch) -> Callable[..., Any]:
    """The **out-of-band act of the approval authority**.

    The factory signs an approval artifact of a step policy with the test key
    and pins the test public key for the duration of the test. Without it the
    gate refuses every provider dispatch.

    The knobs are the refusals the gate has to distinguish:

    * ``step_id`` - an approval of another step;
    * ``call_sites`` - an approval that covers other call sites;
    * ``policy_payload`` - an approval of another policy;
    * ``corrupt_signature`` - a signature that does not verify;
    * ``pin_key=False`` - no key at all: the repository pins none.
    """

    def factory(
        policy: Any,
        call_sites: Optional[Iterable[str]] = None,
        step_id: Optional[str] = None,
        approved_by: str = "test-approver",
        policy_payload: Optional[Mapping[str, Any]] = None,
        approved_policy: Optional[Any] = None,
        pin_key: bool = True,
        corrupt_signature: bool = False,
        dispatch_envelope: Optional[Mapping[str, Any]] = None,
        include_dispatch_envelope: bool = True,
    ) -> Any:
        from core import r1_approval

        source = approved_policy if approved_policy is not None else policy
        payload = {
            "step_id": step_id or source.step_id,
            "approved_by": approved_by,
            "approved_at": source.approved_at,
            "call_sites": sorted(
                call_sites if call_sites is not None else list(r1.FUNCTION_CLASS)
            ),
            "policy": (
                dict(policy_payload)
                if policy_payload is not None
                else source.to_payload()
            ),
            "dispatch_envelope": (
                dict(dispatch_envelope)
                if dispatch_envelope is not None
                else {"schema": "r1-dispatch-envelope/1"}
            ),
        }
        if not include_dispatch_envelope:
            payload.pop("dispatch_envelope")
        signature = sign_payload(r1_approval.canonical_bytes(payload))
        if corrupt_signature:
            signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
        if pin_key:
            monkeypatch.setattr(r1_approval, "pinned_public_key", _public_key)
        return r1_approval.ApprovalArtifact(payload=payload, signature=signature)

    return factory


@pytest.fixture
def signed_approval(approval_authority) -> Callable[..., Any]:
    """The **signed approval artifact** of a step policy.

    The artifact is data: the gate verifies the signature itself, at dispatch
    time, against the pinned public key.
    """
    return approval_authority
