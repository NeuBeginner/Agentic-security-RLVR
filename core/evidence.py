"""
core/evidence.py

Trusted evidence contract (Reward Specification 2.0.0).

THE PROBLEM THIS SOLVES
-----------------------
A reward must never be more trustworthy than the evidence it is derived from.
The previous implementation decided that an exploit breached a security
invariant by GREPPING THE LOGS for the marker `[INVARIANT_BREACHED`. That marker
is printed by the model-controlled exploit itself, so any candidate could have
printed it and looked like a successful attack.

THE TRUSTED CHANNEL
-------------------
The verdict now comes from a single, repository-owned source: the STRUCTURED
test result of the immutable harness suite, read from forge's JSON output.

    suite path  == test/<Target>Harness.t.sol     (owned by the repository)
    test name   == testExploit
    status      == "Success"  -> the harness returned normally  -> BREACH
    status      == "Failure"  -> the harness reverted:
                                    reason starts with EXPLOIT_FAILED -> NO_BREACH
                                    any other reason                   -> EXEC_REVERT
    no trusted suite / no result                              -> UNKNOWN (fail-closed)

HARNESS CONTRACT (enforced by tests/test_harness_contract.py)
--------------------------------------------------------------
1. `testExploit` RETURNS NORMALLY only when the invariant was breached.
2. `testExploit` REVERTS with a reason starting with `EXPLOIT_FAILED` when the
   invariant held (the exploit ran but did not breach).
3. The harness source lives in the repository and is never supplied by the model.

ANTI-FORGERY
------------
Because the verdict is read from the harness suite only, a candidate cannot
reach it:
  * the candidate may not import the Foundry test framework (it could inject its
    own `testExploit` suite, which forge would collect as a passing test);
  * the candidate may not declare a public/external `test*` function;
  * the candidate may not import the console library (it could forge the log
    marker).
All three are rejected as security violations before Foundry is even invoked.
"""

from __future__ import annotations

from enum import Enum


class HarnessVerdict(str, Enum):
    """Verdict of the immutable, repository-owned verification harness."""

    BREACH = "BREACH"
    NO_BREACH = "NO_BREACH"
    EXEC_REVERT = "EXEC_REVERT"
    UNKNOWN = "UNKNOWN"


# The harness reverts with this prefix when the invariant held.
HARNESS_NO_BREACH_REASON_PREFIX = "EXPLOIT_FAILED"

# The single test entrypoint of the trusted harness.
HARNESS_TEST_NAME = "testExploit"


def trusted_harness_suite_prefix(target_name: str) -> str:
    """Path prefix of the repository-owned harness suite inside the sandbox."""
    return f"test/{target_name}Harness.t.sol"


def is_trusted_breach_verdict(verdict: str) -> bool:
    """True only for the explicit, trusted breach verdict."""
    return str(verdict or "").strip().upper() == HarnessVerdict.BREACH.value
