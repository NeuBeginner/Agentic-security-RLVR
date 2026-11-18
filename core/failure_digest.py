"""
core/failure_digest.py
======================

The concrete reason why a candidate failed, read out of the Forge trace.

The verdict of the evaluator says **that** the candidate failed (``RUNTIME_REVERT``
or ``SAFE_RUN``). On its own that statement is useless for the next attempt: the
refinement loop has to repair the candidate, and a verdict without a reason
leaves it guessing. This module reads the reason out of the evidence that the
trusted harness produced - the trace of the failing call.

What is read
------------
* ``EXPLOIT_FAILED: ...`` - the message of the trusted harness: it says which
  invariant was still held;
* the revert reason of the JSON report of the test;
* ``OutOfFunds`` and its relatives - the EVM refused to send more ETH than the
  contract held;
* the call that failed - its address, its selector and the value it carried.

The digest is a **description** of the observed trace, never a guess: it is
built only out of lines that are really in the output of the harness.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence

#: The markers of the EVM error "the contract does not hold enough ETH".
OUT_OF_FUNDS_MARKERS = (
    "OutOfFunds",
    "InsufficientBalance",
    "insufficient balance",
    "insufficient funds",
)

#: The marker of the message of the trusted harness.
EXPLOIT_FAILED_MARKER = "EXPLOIT_FAILED"

#: The glyphs of the tree of the Foundry trace.
_TREE_GLYPHS = "│├└─ "

#: The value of a call in the trace: ``[value: 1000000000000000000]``.
_VALUE_PATTERN = re.compile(r"\[value:\s*([^\]]+)\]")


def _clean_trace_line(line: str) -> str:
    """One line of the trace, without the glyphs of the tree."""
    return line.strip().strip(_TREE_GLYPHS).strip()


def _failing_call(haystack: str) -> Optional[str]:
    """
    The call that failed: its address, its selector and the value it carried.

    A call that reverted is preferred; a call that carried a value is the next
    choice, because a call that sends ETH is the one that fails with
    ``OutOfFunds``. The last call of the trace is the fallback, so the digest
    still names the call when the trace says nothing more.
    """
    reverted: Optional[str] = None
    valued: Optional[str] = None
    any_call: Optional[str] = None
    for line in haystack.splitlines():
        if "::" not in line:
            continue
        any_call = line
        if "[Revert]" in line or "Revert]" in line:
            reverted = line
            continue
        if _VALUE_PATTERN.search(line):
            valued = line
    chosen = reverted or valued or any_call
    if chosen is None:
        return None
    return _clean_trace_line(chosen)


def extract_failure_reason(
    stdout: str = "",
    stderr: str = "",
    revert_reason: Optional[str] = None,
    decoded_logs: Optional[Sequence[str]] = None,
) -> str:
    """
    The concrete reason why the candidate failed, or an empty string.

    The reason is assembled out of the lines that are really in the output of
    the trusted harness; nothing is invented. When the trace says nothing that
    this module understands, the digest is empty - and the caller keeps its own
    wording.
    """
    haystack = "\n".join(
        [stdout or "", stderr or "", "\n".join(str(log) for log in (decoded_logs or []))]
    )

    parts: List[str] = []

    # 1. The message of the trusted harness: it names the invariant that held.
    for line in haystack.splitlines():
        if EXPLOIT_FAILED_MARKER in line:
            parts.append(_clean_trace_line(line))
            break

    # 2. The revert reason of the JSON report of the test.
    if revert_reason:
        parts.append(f"revert reason: {str(revert_reason).strip()}")

    # 3. OutOfFunds and its relatives.
    for line in haystack.splitlines():
        if any(marker in line for marker in OUT_OF_FUNDS_MARKERS):
            parts.append(_clean_trace_line(line))
            break

    # 4. The call that failed: its address, its selector and its value.
    failing_call = _failing_call(haystack)
    if failing_call:
        parts.append(f"failing call: {failing_call}")

    # The same reason twice is one reason.
    unique: List[str] = []
    for part in parts:
        if part and part not in unique:
            unique.append(part)

    return "; ".join(unique)


__all__ = [
    "OUT_OF_FUNDS_MARKERS",
    "EXPLOIT_FAILED_MARKER",
    "extract_failure_reason",
]
