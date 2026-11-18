"""
tests/test_failure_digest.py
============================

The concrete reason of a failed candidate, read out of the trace of the
trusted harness.

A verdict that says only "the candidate failed" leaves the refinement loop
guessing. These tests pin down what the digest reads out of the trace - and
what it must never invent.
"""

from __future__ import annotations

import json

from core.failure_digest import extract_failure_reason

#: A trace of a candidate that sends more ETH than it holds.
OUT_OF_FUNDS_TRACE = """
├─ [12345] ExploitModule::runExploit()
│   ├─ [0] Vault::deposit() [value: 1000000000000000000]
│   └─ ← [Revert] OutOfFunds()
"""

#: A trace of a candidate that reached the vulnerable code but did not breach
#: the invariant.
EXPLOIT_FAILED_TRACE = """
├─ [12345] ExploitModule::runExploit()
│   ├─ [0] LendingLiquidation::liquidateDefective(address:0xdddddddddddddddddddddddddddddddddddd)
│   └─ ← [Revert] EXPLOIT_FAILED: Collateral accounting preserved
"""


def test_the_digest_names_the_out_of_funds_and_the_failing_call():
    """OutOfFunds and the call that carried the value are the evidence."""
    digest = extract_failure_reason(stdout=OUT_OF_FUNDS_TRACE)

    assert "OutOfFunds" in digest
    assert "Vault::deposit()" in digest
    assert "value: 1000000000000000000" in digest


def test_the_digest_carries_the_message_of_the_harness():
    """The message of the harness names the invariant that was still held."""
    digest = extract_failure_reason(stdout=EXPLOIT_FAILED_TRACE)

    assert "EXPLOIT_FAILED: Collateral accounting preserved" in digest
    assert "LendingLiquidation::liquidateDefective" in digest


def test_the_digest_carries_the_revert_reason_of_the_report():
    """The revert reason of the JSON report is part of the reason."""
    digest = extract_failure_reason(
        stdout="",
        revert_reason="execution reverted: true",
    )

    assert "execution reverted: true" in digest


def test_the_digest_invents_nothing():
    """A trace that says nothing the digest understands yields an empty digest."""
    assert extract_failure_reason(stdout="") == ""
    assert extract_failure_reason(stdout="some unrelated output") == ""


def test_the_digest_reads_the_decoded_logs():
    """
    The decoded logs of the test are part of the evidence.

    A log that carries the message of the trusted harness is part of the
    reason - a log that says nothing the digest understands is not.
    """
    digest = extract_failure_reason(
        decoded_logs=["EXPLOIT_FAILED: Collateral accounting preserved"]
    )
    assert "EXPLOIT_FAILED: Collateral accounting preserved" in digest

    # A log without a known marker is not a reason - the digest never invents
    # one out of text the candidate could have printed itself.
    assert extract_failure_reason(decoded_logs=["hello from the candidate"]) == ""


def test_the_digest_extracts_deepest_failing_call_from_forge_json_trace():
    """Silent EvmError: Revert in Forge --json (BIZ-01 / LIQ-01) must still name the deepest failing CALL."""
    forge_json = json.dumps({
        "test/LendingLiquidationHarness.t.sol:LendingLiquidationHarness": {
            "duration": "364us",
            "test_results": {
                "testExploit()": {
                    "status": "Failure",
                    "reason": "EvmError: Revert",
                    "traces": [
                        [
                            "Execution",
                            {
                                "arena": [
                                    {
                                        "idx": 0,
                                        "parent": None,
                                        "children": [1, 2],
                                        "trace": {
                                            "depth": 0,
                                            "kind": "CALL",
                                            "success": False,
                                            "address": "0x7fa9385be102ac3eac297483dd6233d62b3e1496",
                                            "value": "0x0",
                                            "data": "0xca1ba028",
                                            "output": "0x",
                                        },
                                    },
                                    {
                                        "idx": 1,
                                        "parent": 0,
                                        "children": [],
                                        "trace": {
                                            "depth": 1,
                                            "kind": "CREATE",
                                            "success": True,
                                            "address": "0x2e234dae75c793f67a35089c9d99245e1c58470b",
                                            "value": "0x0",
                                            "data": "0x6080",
                                            "output": "0x6080",
                                        },
                                    },
                                    {
                                        "idx": 2,
                                        "parent": 0,
                                        "children": [3],
                                        "trace": {
                                            "depth": 1,
                                            "kind": "CALL",
                                            "success": False,
                                            "address": "0x2e234dae75c793f67a35089c9d99245e1c58470b",
                                            "value": "0x0",
                                            "data": "0x28f07383",
                                            "output": "0x",
                                        },
                                    },
                                    {
                                        "idx": 3,
                                        "parent": 2,
                                        "children": [],
                                        "trace": {
                                            "depth": 2,
                                            "kind": "CALL",
                                            "success": False,
                                            "address": "0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f",
                                            "value": "0xde0b6b3a7640000",
                                            "data": "0x350245c2",
                                            "output": "0x",
                                        },
                                    },
                                ]
                            },
                        ]
                    ],
                }
            },
        }
    })

    digest = extract_failure_reason(stdout=forge_json, revert_reason="EvmError: Revert")
    assert "revert reason: EvmError: Revert" in digest
    assert "CALL 0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f::0x350245c2" in digest
    assert "0xde0b6b3a7640000 (1000000000000000000 wei)" in digest


def test_the_digest_extracts_decoded_delegatecall_fields_when_present():
    """Decoded label, function signature, and return_data are extracted for DELEGATECALL/STATICCALL."""
    forge_json = json.dumps({
        "test/Sample.t.sol:SampleTest": {
            "test_results": {
                "testExploit()": {
                    "traces": [
                        [
                            "Execution",
                            {
                                "arena": [
                                    {
                                        "idx": 0,
                                        "parent": None,
                                        "children": [1],
                                        "trace": {
                                            "depth": 0,
                                            "kind": "CALL",
                                            "success": False,
                                            "address": "0x1111111111111111111111111111111111111111",
                                            "value": "0x0",
                                            "data": "0x12345678",
                                        },
                                    },
                                    {
                                        "idx": 1,
                                        "parent": 0,
                                        "children": [],
                                        "trace": {
                                            "depth": 1,
                                            "kind": "DELEGATECALL",
                                            "success": False,
                                            "address": "0x2222222222222222222222222222222222222222",
                                            "value": "0x0",
                                            "data": "0xabcdef01",
                                            "status": "Revert",
                                            "decoded": {
                                                "label": "ImplContract",
                                                "call_data": {"signature": "execute(uint256)"},
                                                "return_data": "Unauthorized",
                                            },
                                        },
                                    },
                                ]
                            },
                        ]
                    ]
                }
            }
        }
    })

    digest = extract_failure_reason(stdout=forge_json)
    assert "DELEGATECALL ImplContract (0x2222222222222222222222222222222222222222)::execute(uint256)" in digest
    assert "status: Revert" in digest
    assert "revert: Unauthorized" in digest


def test_the_digest_never_embeds_raw_forge_json_for_out_of_funds():
    """Single-line Forge --json with OutOfFunds must emit a short marker and failing call, never raw JSON."""
    forge_json = json.dumps({
        "test/FeeShareYieldVaultHarness.t.sol:FeeShareYieldVaultHarness": {
            "duration": "422us",
            "test_results": {
                "testExploit()": {
                    "status": "Failure",
                    "reason": "EvmError: Revert",
                    "traces": [
                        [
                            "Execution",
                            {
                                "arena": [
                                    {
                                        "idx": 0,
                                        "parent": None,
                                        "children": [1],
                                        "trace": {
                                            "depth": 0,
                                            "kind": "CALL",
                                            "success": False,
                                            "status": "Revert",
                                            "address": "0x7fa9385be102ac3eac297483dd6233d62b3e1496",
                                            "value": "0x0",
                                            "data": "0xca1ba028",
                                        },
                                    },
                                    {
                                        "idx": 1,
                                        "parent": 0,
                                        "children": [],
                                        "trace": {
                                            "depth": 2,
                                            "kind": "CALL",
                                            "success": False,
                                            "status": "OutOfFunds",
                                            "address": "0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f",
                                            "value": "0xde0b6b3a7640000",
                                            "data": "0xd0e30db0",
                                        },
                                    },
                                ]
                            },
                        ]
                    ],
                }
            },
        }
    })

    digest = extract_failure_reason(stdout=forge_json, revert_reason="EvmError: Revert")
    assert "{" not in digest
    assert "OutOfFunds" in digest
    assert "failing call: CALL 0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f::0xd0e30db0" in digest
    assert "0xde0b6b3a7640000 (1000000000000000000 wei)" in digest
    assert "status: OutOfFunds" in digest


def test_the_digest_never_embeds_raw_forge_json_for_exploit_failed():
    """Single-line Forge --json with EXPLOIT_FAILED must extract only the short message, never raw JSON."""
    forge_json = json.dumps({
        "test/FeeShareYieldVaultHarness.t.sol:FeeShareYieldVaultHarness": {
            "duration": "300us",
            "test_results": {
                "testExploit()": {
                    "status": "Failure",
                    "reason": "EXPLOIT_FAILED: Yield fees protected",
                    "traces": [
                        [
                            "Execution",
                            {
                                "arena": [
                                    {
                                        "idx": 0,
                                        "parent": None,
                                        "children": [],
                                        "trace": {
                                            "depth": 0,
                                            "kind": "CALL",
                                            "success": False,
                                            "status": "Revert",
                                            "address": "0x7fa9385be102ac3eac297483dd6233d62b3e1496",
                                            "value": "0x0",
                                            "data": "0xca1ba028",
                                        },
                                    },
                                ]
                            },
                        ]
                    ],
                }
            },
        }
    })

    digest = extract_failure_reason(stdout=forge_json, revert_reason="EXPLOIT_FAILED: Yield fees protected")
    assert "{" not in digest
    assert "EXPLOIT_FAILED: Yield fees protected" in digest
    assert "failing call: CALL 0x7fa9385be102ac3eac297483dd6233d62b3e1496::0xca1ba028" in digest
