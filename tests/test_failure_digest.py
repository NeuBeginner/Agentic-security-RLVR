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
