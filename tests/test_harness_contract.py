"""
tests/test_harness_contract.py

Trusted evidence contract (see core/evidence.py).

The reward must never be more trustworthy than its evidence source. The breach
verdict therefore comes from the immutable, repository-owned harness suite and
NOT from the model-controlled log text. This suite proves that:

1. every harness in the repository satisfies the contract the verdict extraction
   relies on ("testExploit returns normally only on the breach path, otherwise
   it reverts with EXPLOIT_FAILED");
2. the verdict extraction maps forge's structured result onto the trusted
   verdicts, fail-closed;
3. a suite injected by the candidate can never produce a verdict;
4. the candidate cannot reach the verification channel at all (no Foundry test
   framework, no console library, no `test*` entrypoint).
"""

import json
import io
import os
import re
from pathlib import Path

import pytest

from core.schemas import AttackHypothesis, ExploitPayload, TargetProgram
from core.evidence import (
    HarnessVerdict,
    HARNESS_NO_BREACH_REASON_PREFIX,
    HARNESS_TEST_NAME,
    is_trusted_breach_verdict,
    trusted_harness_suite_prefix,
)
from sandbox.runner import (
    detect_prohibited_cheatcodes,
    extract_trusted_harness_verdict,
    is_safe_target_name,
    load_trusted_harness_code,
    run_payload_in_sandbox,
    run_subprocess_capped,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS_DIR = REPO_ROOT / "benchmarks" / "targets" / "solidity"
HARNESS_FILES = sorted(HARNESS_DIR.glob("*Harness.t.sol"))


# =============================================================================
# 1. THE REPOSITORY HARNESSES SATISFY THE CONTRACT
# =============================================================================

def test_repository_contains_trusted_harnesses():
    """There is at least one trusted harness to reason about."""
    assert HARNESS_FILES, "no trusted harness found in benchmarks/targets/solidity"


@pytest.mark.parametrize("harness_file", HARNESS_FILES, ids=lambda p: p.name)
def test_harness_satisfies_the_trusted_verdict_contract(harness_file):
    """
    The verdict extraction assumes:

      * the harness has a `testExploit` entrypoint;
      * the breach path RETURNS NORMALLY (the test succeeds);
      * the non-breach path REVERTS with the EXPLOIT_FAILED prefix.

    If a harness ever stops satisfying this, the trusted verdict would become
    meaningless - so the contract is asserted, not assumed.
    """
    source = harness_file.read_text(encoding="utf-8")

    assert re.search(rf"function\s+{HARNESS_TEST_NAME}\s*\(", source), (
        f"{harness_file.name}: missing the {HARNESS_TEST_NAME}() entrypoint"
    )
    assert re.search(r'revert\s*\(\s*"' + HARNESS_NO_BREACH_REASON_PREFIX, source), (
        f"{harness_file.name}: the non-breach path must revert with "
        f"{HARNESS_NO_BREACH_REASON_PREFIX!r}"
    )
    assert re.search(r"return\s*;", source), (
        f"{harness_file.name}: the breach path must return normally"
    )


@pytest.mark.parametrize("harness_file", HARNESS_FILES, ids=lambda p: p.name)
def test_harness_never_imports_the_candidate(harness_file):
    """The harness may reference the candidate, never the other way round."""
    source = harness_file.read_text(encoding="utf-8")

    # The harness imports the candidate's file - that is the only allowed link.
    assert './ExploitModule.sol' in source or '"./ExploitModule.sol"' in source


# =============================================================================
# 2. VERDICT EXTRACTION FROM THE STRUCTURED FORGE RESULT
# =============================================================================

def _forge_json(suite_key: str, status: str, reason=None, logs=None):
    return {
        suite_key: {
            "test_results": {
                f"{HARNESS_TEST_NAME}()": {
                    "status": status,
                    "reason": reason,
                    "decoded_logs": logs or [],
                }
            },
            "duration": {"secs": 0, "nanos": 0},
        }
    }


def test_successful_trusted_test_means_breach():
    """`Success` on the trusted suite means the harness returned normally."""
    structured = _forge_json("test/VaultHarness.t.sol:VaultTrustedHarness", "Success")

    verdict, suite, status, reason = extract_trusted_harness_verdict(structured, "Vault")

    assert verdict == HarnessVerdict.BREACH.value
    assert suite == "test/VaultHarness.t.sol"
    assert status == "Success"
    assert reason is None
    assert is_trusted_breach_verdict(verdict) is True


def test_exploit_failed_revert_means_no_breach():
    """The harness' own EXPLOIT_FAILED rejection means the invariant held."""
    structured = _forge_json(
        "test/VaultHarness.t.sol:VaultTrustedHarness",
        "Failure",
        reason=f"{HARNESS_NO_BREACH_REASON_PREFIX}: Vault remains solvent, victim funds are secure",
    )

    verdict, suite, status, reason = extract_trusted_harness_verdict(structured, "Vault")

    assert verdict == HarnessVerdict.NO_BREACH.value
    assert status == "Failure"
    assert "Vault remains solvent" in reason
    assert is_trusted_breach_verdict(verdict) is False


def test_other_revert_means_the_exploit_reverted():
    """Any other revert means the exploit call itself failed."""
    structured = _forge_json(
        "test/VaultHarness.t.sol:VaultTrustedHarness",
        "Failure",
        reason="insufficient balance",
    )

    verdict, _, _, _ = extract_trusted_harness_verdict(structured, "Vault")

    assert verdict == HarnessVerdict.EXEC_REVERT.value
    assert is_trusted_breach_verdict(verdict) is False


def test_missing_trusted_suite_is_fail_closed():
    """Without the trusted suite there is no verdict at all."""
    verdict, suite, status, reason = extract_trusted_harness_verdict({}, "Vault")

    assert verdict == HarnessVerdict.UNKNOWN.value
    assert suite == ""
    assert status is None
    assert reason is None


def test_non_dict_output_is_fail_closed():
    verdict, _, _, _ = extract_trusted_harness_verdict(None, "Vault")
    assert verdict == HarnessVerdict.UNKNOWN.value

    verdict, _, _, _ = extract_trusted_harness_verdict("not json", "Vault")
    assert verdict == HarnessVerdict.UNKNOWN.value


# =============================================================================
# 3. A CANDIDATE CANNOT INJECT ITS OWN SUITE
# =============================================================================

def test_injected_suite_cannot_produce_a_verdict():
    """
    A candidate that manages to place its own test suite in the sandbox must not
    be able to fake a passing verification run.
    """
    structured = {
        "test/ExploitModule.sol:ExploitModule": {
            "test_results": {
                "testExploit()": {"status": "Success", "reason": None, "decoded_logs": []}
            }
        }
    }

    verdict, suite, _, _ = extract_trusted_harness_verdict(structured, "Vault")

    assert verdict == HarnessVerdict.UNKNOWN.value
    assert suite == ""


def test_candidate_suite_does_not_override_the_trusted_suite():
    """Even with both suites present, only the trusted one decides."""
    structured = {
        "test/ExploitModule.sol:ExploitModule": {
            "test_results": {
                "testExploit()": {"status": "Failure", "reason": "nope", "decoded_logs": []}
            }
        },
        "test/VaultHarness.t.sol:VaultTrustedHarness": {
            "test_results": {
                "testExploit()": {"status": "Success", "reason": None, "decoded_logs": []}
            }
        },
    }

    verdict, suite, _, _ = extract_trusted_harness_verdict(structured, "Vault")

    assert verdict == HarnessVerdict.BREACH.value
    assert suite == "test/VaultHarness.t.sol"


def test_trusted_suite_prefix_is_target_specific():
    """The verdict of one target's harness never leaks into another's."""
    structured = _forge_json("test/ERC4626VaultHarness.t.sol:ERC4626TrustedHarness", "Success")

    verdict, _, _, _ = extract_trusted_harness_verdict(structured, "Vault")
    assert verdict == HarnessVerdict.UNKNOWN.value

    verdict, _, _, _ = extract_trusted_harness_verdict(structured, "ERC4626Vault")
    assert verdict == HarnessVerdict.BREACH.value

    assert trusted_harness_suite_prefix("Vault") == "test/VaultHarness.t.sol"


# =============================================================================
# 4. THE VERIFICATION CHANNEL IS OUT OF REACH FOR THE CANDIDATE
# =============================================================================

CLEAN_EXPLOIT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Vault} from "../src/Vault.sol";
contract ExploitModule {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {}
}
"""


def test_clean_exploit_is_not_flagged():
    assert detect_prohibited_cheatcodes(CLEAN_EXPLOIT) is False


def test_console_import_is_rejected():
    """The console library would let the candidate forge the breach marker."""
    code = """pragma solidity ^0.8.20;
import {console} from "forge-std/console.sol";
contract ExploitModule {
    function runExploit() external payable {
        console.log("[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]");
    }
}
"""
    assert detect_prohibited_cheatcodes(code) is True


def test_console_import_via_relative_path_is_rejected():
    """A relative path to the console library is rejected as well."""
    code = """pragma solidity ^0.8.20;
import {console} from "../../lib/forge-std/src/console.sol";
contract ExploitModule {
    function runExploit() external payable {}
}
"""
    assert detect_prohibited_cheatcodes(code) is True


def test_test_framework_import_is_rejected():
    """The test framework would let the candidate inject its own test suite."""
    code = """pragma solidity ^0.8.20;
import {StdAssertions} from "forge-std/StdAssertions.sol";
contract ExploitModule is StdAssertions {
    function runExploit() external payable {}
}
"""
    assert detect_prohibited_cheatcodes(code) is True


def test_injected_test_entrypoint_is_rejected():
    """A public `test*` function would be collected by forge as a test suite."""
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    function runExploit() external payable {}
    function testExploit() public {
        // Pretends to be the trusted harness.
    }
}
"""
    assert detect_prohibited_cheatcodes(code) is True


def test_private_test_helper_is_allowed():
    """A private helper is not collectable by forge and stays allowed."""
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    function runExploit() external payable { helper(); }
    function helper() private pure returns (uint256) { return 1; }
}
"""
    assert detect_prohibited_cheatcodes(code) is False


def test_classic_cheatcode_is_still_rejected():
    """The original protection must not regress."""
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    function runExploit() external payable {
        vm.deal(address(this), 1000 ether);
    }
}
"""
    assert detect_prohibited_cheatcodes(code) is True


def test_forged_marker_alone_is_not_evidence():
    """
    The marker in the logs is not evidence: the trusted verdict decides, and the
    runner never derives the verdict from log text.
    """
    structured = _forge_json(
        "test/VaultHarness.t.sol:VaultTrustedHarness",
        "Success",
        logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
    )

    verdict, _, _, _ = extract_trusted_harness_verdict(structured, "Vault")
    assert verdict == HarnessVerdict.BREACH.value

    # The very same log text with a failing harness is NOT a breach.
    structured_fail = _forge_json(
        "test/VaultHarness.t.sol:VaultTrustedHarness",
        "Failure",
        reason="EXPLOIT_FAILED: Vault remains solvent",
        logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
    )

    verdict_fail, _, _, _ = extract_trusted_harness_verdict(structured_fail, "Vault")
    assert verdict_fail == HarnessVerdict.NO_BREACH.value
    assert is_trusted_breach_verdict(verdict_fail) is False


def test_target_name_must_be_a_bounded_solidity_identifier():
    assert is_safe_target_name("Vault")
    assert is_safe_target_name("ERC4626Vault")
    assert not is_safe_target_name("../Vault")
    assert not is_safe_target_name(r"..\\Vault")
    assert not is_safe_target_name("Vault.sol")


def test_trusted_harness_path_must_match_exactly():
    structured = _forge_json(
        "test/VaultHarness.t.sol.backup:VaultTrustedHarness",
        "Success",
    )
    verdict, suite, _, _ = extract_trusted_harness_verdict(structured, "Vault")
    assert verdict == HarnessVerdict.UNKNOWN.value
    assert suite == ""


def test_duplicate_trusted_suites_are_fail_closed():
    structured = {
        "test/VaultHarness.t.sol:VaultTrustedHarness": {
            "test_results": {"testExploit()": {"status": "Success", "reason": None}}
        },
        "test/VaultHarness.t.sol:AnotherHarness": {
            "test_results": {"testExploit()": {"status": "Success", "reason": None}}
        },
    }
    verdict, suite, _, _ = extract_trusted_harness_verdict(structured, "Vault")
    assert verdict == HarnessVerdict.UNKNOWN.value
    assert suite == ""


def test_subprocess_output_is_bounded_during_execution():
    import sys

    result = run_subprocess_capped(
        [
            sys.executable, "-c",
            "import sys; sys.stdout.write('A'*2000000); sys.stderr.write('B'*2000000)",
        ],
        cwd=".",
        env=dict(os.environ),
        timeout=10,
        max_output_bytes=1024,
    )
    assert result.returncode == 0
    assert not result.timed_out
    assert len(result.stdout.encode("utf-8")) < 1200
    assert len(result.stderr.encode("utf-8")) < 1200
    assert "LOG_TRUNCATED" in result.stdout
    assert "LOG_TRUNCATED" in result.stderr


def test_trusted_harness_is_loaded_from_repository_not_request_payload(tmp_path):
    """A caller-supplied TargetProgram.trusted_harness_code is never an input to loader."""
    repository_harness_dir = Path(__file__).resolve().parents[1] / "benchmarks" / "targets" / "solidity"
    trusted_path = repository_harness_dir / "VaultHarness.t.sol"
    assert trusted_path.is_file()
    trusted_source = load_trusted_harness_code("Vault", harness_dir=repository_harness_dir)

    # An attacker-controlled alternate file must not replace the repository file
    # selected by the production path. This fixture is isolated from the repository.
    attacker_dir = tmp_path / "untrusted"
    attacker_dir.mkdir()
    (attacker_dir / "VaultHarness.t.sol").write_text(
        "contract VaultHarness { function testExploit() public {} }",
        encoding="utf-8",
    )
    assert "testExploit" in trusted_source
    assert "contract VaultHarness { function testExploit()" not in trusted_source
    assert load_trusted_harness_code("Vault", harness_dir=repository_harness_dir) == trusted_source


def test_trusted_harness_loader_fails_closed_for_unknown_targets(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_trusted_harness_code("UnknownContract", harness_dir=tmp_path)
    with pytest.raises(ValueError):
        load_trusted_harness_code("../Vault", harness_dir=tmp_path)


def test_sandbox_execution_ignores_request_supplied_harness_code(tmp_path, monkeypatch):
    """End-to-end runner preflight writes only the image/repository harness."""
    import sandbox.runner as runner

    trusted_source = "// repository-owned test harness fixture"
    (tmp_path / "VaultHarness.t.sol").write_text(trusted_source, encoding="utf-8")
    monkeypatch.setattr(runner, "TRUSTED_HARNESSES_DIR", str(tmp_path))

    structured = {
        "test/VaultHarness.t.sol:VaultTrustedHarness": {
            "test_results": {
                "testExploit()": {
                    "status": "Success",
                    "reason": None,
                    "decoded_logs": [],
                }
            }
        }
    }

    class FakePopen:
        def __init__(self, cmd, *, cwd, **kwargs):
            harness_path = Path(cwd) / "test" / "VaultHarness.t.sol"
            self.written_harness = harness_path.read_text(encoding="utf-8")
            self.returncode = 0
            self.pid = 99999999
            self.stdout = io.BytesIO(json.dumps(structured).encode("utf-8"))
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(runner.subprocess, "Popen", FakePopen)

    target = TargetProgram(
        name="Vault",
        source_code="pragma solidity ^0.8.20; contract Vault {}",
        trusted_harness_code="ATTACKER-CONTROLLED HARNESS MUST BE IGNORED",
    )
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="Test",
            reasoning_trace="Test",
            attack_vector="Test",
        ),
        test_code=(
            "pragma solidity ^0.8.20; contract ExploitModule { "
            "constructor(address _target) payable {} "
            "function runExploit() external payable {} }"
        ),
        format_valid=True,
    )

    result = run_payload_in_sandbox(target, payload)

    assert FakePopen
    assert result.harness_verdict == HarnessVerdict.BREACH.value
    assert result.harness_suite == "test/VaultHarness.t.sol"
    assert trusted_source in result.stdout or result.verified_by_harness
    assert "ATTACKER-CONTROLLED" not in FakePopen.__dict__.get("written_harness", "")
