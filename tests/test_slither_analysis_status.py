"""
tests/test_slither_analysis_status.py
=====================================

The regression tests of the classification of a Slither run.

Why these tests exist
---------------------
The acceptance evidence of the CPU-only audit service carried
``slither_exit_code: 255`` next to ``analysis_mode: "slither"`` and a report with
findings - and the gate accepted it. The report was fine, but the repository had
decided that "Slither ran" by the mere presence of the JSON report. That is wrong:

* the Slither CLI writes the JSON report **before** it leaves with a non-zero code;
* with its default ``--fail-on pedantic`` the CLI leaves with ``sys.exit(-1)``
  (the shell code 255) as soon as it found anything - the analysis itself
  succeeded;
* the very same code is used when the analysis itself failed.

So the exit code alone proves nothing, and a report with findings proves nothing
either. These tests pin down the classification that replaced that rule:

1. the exit code 0 with a valid report is a **completed** analysis;
2. the exit code 255 with a valid report is a completed analysis **only** when the
   findings policy of the CLI was in effect - otherwise it is a **partial** run;
3. a report that states a failure, an unusable report and a timeout are
   **partial** runs, never a completed analysis;
4. a run without a report is a **fallback** - the deterministic heuristics of the
   repository, and never the result of an analysis;
5. the evidence of a run has to be consistent: the exit code, the status of the
   analysis, the validity of the report and the fallback flag may not contradict
   each other.

Nothing in this file performs a provider call, a deployment or a network access:
the whole suite is local and deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

_ROOT = Path(__file__).resolve().parent.parent

from core.slither_status import (  # noqa: E402
    DISPOSITION_ANALYSIS_ERROR,
    DISPOSITION_CLEAN_EXIT,
    DISPOSITION_FINDINGS_POLICY,
    DISPOSITION_NO_REPORT,
    DISPOSITION_NOT_RUN,
    DISPOSITION_TIMEOUT,
    DISPOSITION_UNEXPLAINED_EXIT,
    DISPOSITION_UNPARSABLE_REPORT,
    MODE_FALLBACK,
    MODE_REFUSED,
    MODE_SLITHER,
    MODE_UNAVAILABLE,
    SLITHER_ABORT_EXIT_CODE,
    STATUS_COMPLETED,
    STATUS_FALLBACK,
    STATUS_PARTIAL,
    STATUS_UNAVAILABLE,
    classify_slither_outcome,
    static_analysis_evidence_is_consistent,
)
from sandbox import runner as runner_module  # noqa: E402
from sandbox.runner import CappedProcessResult, run_slither_analysis_detailed  # noqa: E402

from core.schemas import TargetProgram  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

#: A minimal report of the Slither CLI: it always writes ``success``, ``error``
#: and ``results``.
def _report(*, success: bool = True, error: Optional[str] = None, detectors: int = 2) -> Dict[str, Any]:
    return {
        "success": success,
        "error": error,
        "results": {
            "detectors": [
                {
                    "check": f"detector-{index}",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": f"finding {index}",
                }
                for index in range(detectors)
            ]
        },
    }


def _record(**overrides: Any) -> Dict[str, Any]:
    """A static analysis record of a completed run, as the service writes it."""
    record: Dict[str, Any] = {
        "analysis_mode": MODE_SLITHER,
        "analysis_status": STATUS_COMPLETED,
        "exit_code_disposition": DISPOSITION_CLEAN_EXIT,
        "slither_exit_code": 0,
        "slither_report_present": True,
        "slither_report_valid": True,
        "slither_report_success": True,
        "fallback_reason": None,
    }
    record.update(overrides)
    return record


def _as_evidence(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    The record of the runner as the service writes it into the evidence.

    The runner names the provenance of the findings ``mode``, the evidence names
    it ``analysis_mode`` - the rest of the fields are the same. A record that is
    already written in the shape of the evidence is returned unchanged.
    """
    if "mode" not in record:
        return record
    evidence = dict(record)
    evidence["analysis_mode"] = evidence.pop("mode")
    return evidence


# ---------------------------------------------------------------------------
# 1. The classification of one invocation
# ---------------------------------------------------------------------------


def test_a_clean_run_with_a_valid_report_is_a_completed_analysis():
    outcome = classify_slither_outcome(
        exit_code=0,
        report=_report(),
        report_present=True,
        report_parsable=True,
    )
    assert outcome["analysis_status"] == STATUS_COMPLETED
    assert outcome["analysis_mode"] == MODE_SLITHER
    assert outcome["exit_code_disposition"] == DISPOSITION_CLEAN_EXIT
    assert outcome["report_valid"] is True
    assert outcome["report_success"] is True


def test_the_findings_policy_exit_code_is_a_completed_analysis():
    """
    The exit code 255 with a valid report is the findings policy of the CLI.

    Slither writes the report before it leaves with ``sys.exit(-1)``, so the
    analysis itself succeeded. That cause is named, not ignored.
    """
    outcome = classify_slither_outcome(
        exit_code=SLITHER_ABORT_EXIT_CODE,
        report=_report(),
        report_present=True,
        report_parsable=True,
        findings_policy_disabled=False,
    )
    assert outcome["analysis_status"] == STATUS_COMPLETED
    assert outcome["analysis_mode"] == MODE_SLITHER
    assert outcome["exit_code_disposition"] == DISPOSITION_FINDINGS_POLICY


def test_the_same_exit_code_without_the_findings_policy_is_a_partial_run():
    """
    With the findings policy disabled the code 255 has no explanation left.

    The run is then partial - a report with findings is not a proof of a
    successful analysis.
    """
    outcome = classify_slither_outcome(
        exit_code=SLITHER_ABORT_EXIT_CODE,
        report=_report(),
        report_present=True,
        report_parsable=True,
        findings_policy_disabled=True,
    )
    assert outcome["analysis_status"] == STATUS_PARTIAL
    assert outcome["analysis_mode"] == MODE_FALLBACK
    assert outcome["exit_code_disposition"] == DISPOSITION_UNEXPLAINED_EXIT


def test_a_report_that_states_a_failure_is_a_partial_run():
    outcome = classify_slither_outcome(
        exit_code=SLITHER_ABORT_EXIT_CODE,
        report=_report(success=False, error="SlitherException: cannot parse"),
        report_present=True,
        report_parsable=True,
    )
    assert outcome["analysis_status"] == STATUS_PARTIAL
    assert outcome["analysis_mode"] == MODE_FALLBACK
    assert outcome["exit_code_disposition"] == DISPOSITION_ANALYSIS_ERROR
    assert outcome["report_error"] == "SlitherException: cannot parse"


def test_a_report_that_cannot_be_parsed_is_a_partial_run():
    outcome = classify_slither_outcome(
        exit_code=1,
        report=None,
        report_present=True,
        report_parsable=False,
    )
    assert outcome["analysis_status"] == STATUS_PARTIAL
    assert outcome["exit_code_disposition"] == DISPOSITION_UNPARSABLE_REPORT


def test_a_run_without_a_report_is_a_fallback():
    outcome = classify_slither_outcome(
        exit_code=127,
        report=None,
        report_present=False,
        report_parsable=False,
    )
    assert outcome["analysis_status"] == STATUS_FALLBACK
    assert outcome["analysis_mode"] == MODE_FALLBACK
    assert outcome["exit_code_disposition"] == DISPOSITION_NO_REPORT


def test_a_timeout_is_never_a_completed_analysis():
    outcome = classify_slither_outcome(
        exit_code=-9,
        report=None,
        report_present=False,
        report_parsable=False,
        timed_out=True,
    )
    assert outcome["analysis_status"] == STATUS_FALLBACK
    assert outcome["exit_code_disposition"] == DISPOSITION_TIMEOUT


# ---------------------------------------------------------------------------
# 2. The consistency of the evidence
# ---------------------------------------------------------------------------


def test_a_consistent_record_is_accepted():
    assert static_analysis_evidence_is_consistent(_record()) is True


def test_a_record_that_claims_slither_with_an_unexplained_exit_code_is_rejected():
    record = _record(
        slither_exit_code=SLITHER_ABORT_EXIT_CODE,
        exit_code_disposition=DISPOSITION_UNEXPLAINED_EXIT,
    )
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is False


def test_a_record_that_claims_slither_with_a_broken_report_is_rejected():
    assert (
        static_analysis_evidence_is_consistent(
            _record(slither_report_valid=False)
        )
        is False
    )


def test_a_record_that_claims_slither_and_a_fallback_at_once_is_rejected():
    assert (
        static_analysis_evidence_is_consistent(
            _record(fallback_reason="slither produced no report")
        )
        is False
    )


def test_a_partial_run_may_not_claim_the_real_slither():
    record = _record(
        analysis_status=STATUS_PARTIAL,
        exit_code_disposition=DISPOSITION_UNEXPLAINED_EXIT,
        slither_exit_code=SLITHER_ABORT_EXIT_CODE,
        fallback_reason="slither left with the code 255",
    )
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is False


def test_a_fallback_run_has_to_name_its_reason():
    record = _record(
        analysis_mode=MODE_FALLBACK,
        analysis_status=STATUS_FALLBACK,
        exit_code_disposition=DISPOSITION_NO_REPORT,
        slither_report_valid=False,
        slither_report_success=None,
        slither_exit_code=127,
    )
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is False
    record["fallback_reason"] = "slither produced no report (exit code 127)"
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is True


def test_an_unavailable_stage_is_consistent_only_when_it_explains_itself():
    record = {
        "analysis_mode": MODE_UNAVAILABLE,
        "analysis_status": STATUS_UNAVAILABLE,
        "exit_code_disposition": DISPOSITION_NOT_RUN,
        "slither_exit_code": None,
        "slither_report_valid": False,
        "slither_report_success": None,
        "fallback_reason": None,
    }
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is True


def test_a_refused_target_is_consistent():
    record = {
        "analysis_mode": MODE_REFUSED,
        "analysis_status": STATUS_UNAVAILABLE,
        "exit_code_disposition": DISPOSITION_NOT_RUN,
        "slither_exit_code": None,
        "slither_report_valid": False,
        "slither_report_success": None,
        "fallback_reason": None,
    }
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is True


# ---------------------------------------------------------------------------
# 3. The runner itself - the code path that produced the ambiguous evidence
# ---------------------------------------------------------------------------


class _FakeSlither:
    """A Slither process that behaves exactly as the test says it behaves."""

    def __init__(
        self,
        *,
        returncode: int,
        report: Optional[Dict[str, Any]] = None,
        write_report: bool = True,
        raw_report: Optional[str] = None,
        stdout: str = "",
        stderr: str = "",
        timed_out: bool = False,
    ) -> None:
        self.returncode = returncode
        self.report = report
        self.write_report = write_report
        self.raw_report = raw_report
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.calls: List[List[str]] = []

    def __call__(self, cmd: list, *, cwd: str, env: dict, timeout: int) -> CappedProcessResult:
        self.calls.append(list(cmd))
        if cmd[-1] == "--version":
            return CappedProcessResult(0, "slither-analyzer 0.11.6", "")
        if "--json" in cmd:
            json_out = cmd[cmd.index("--json") + 1]
            if self.write_report:
                with open(json_out, "w", encoding="utf-8") as handle:
                    if self.raw_report is not None:
                        handle.write(self.raw_report)
                    else:
                        json.dump(self.report or {}, handle)
        return CappedProcessResult(self.returncode, self.stdout, self.stderr, self.timed_out)


def _target() -> TargetProgram:
    return TargetProgram(
        name="Vault",
        source_code=(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract Vault {\n"
            "    mapping(address => uint256) public balances;\n"
            "    function withdrawAll() public { (bool ok, ) = msg.sender.call{value: balances[msg.sender]}(); require(ok); }\n"
            "}\n"
        ),
        invariants=["Depositor Solvency"],
    )


def test_the_runner_reports_a_clean_run_as_a_completed_analysis(monkeypatch):
    fake = _FakeSlither(returncode=0, report=_report())
    monkeypatch.setattr(runner_module, "run_subprocess_capped", fake)

    record = run_slither_analysis_detailed(_target())

    assert record["analysis_status"] == STATUS_COMPLETED
    assert record["mode"] == MODE_SLITHER
    assert record["slither_exit_code"] == 0
    assert record["exit_code_disposition"] == DISPOSITION_CLEAN_EXIT
    assert record["slither_report_valid"] is True
    assert record["slither_report_success"] is True
    assert record["finding_count"] == 2
    assert record["fallback_reason"] is None
    assert "--fail-none" in record["slither_argv"]
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is True


def test_the_runner_never_marks_a_run_with_a_findings_exit_code_as_slither(monkeypatch):
    """
    The regression of the ambiguous evidence.

    A run that leaves with the code 255 and leaves a report behind is not a
    completed analysis when the findings policy was disabled - the findings of
    such a run are the heuristics of the repository, and the report itself is
    kept as the evidence of a partial run.
    """
    fake = _FakeSlither(
        returncode=SLITHER_ABORT_EXIT_CODE,
        report=_report(),
        stdout="Vault analyzed (1 contracts with 40 detectors), 2 result(s) found",
    )
    monkeypatch.setattr(runner_module, "run_subprocess_capped", fake)

    record = run_slither_analysis_detailed(_target())

    assert record["analysis_status"] == STATUS_PARTIAL
    assert record["mode"] == MODE_FALLBACK
    assert record["slither_exit_code"] == SLITHER_ABORT_EXIT_CODE
    assert record["exit_code_disposition"] == DISPOSITION_UNEXPLAINED_EXIT
    assert record["slither_report_valid"] is True
    # The findings of the report are evidence of the partial run, not of the analysis.
    assert record["partial_finding_count"] == 2
    assert record["finding_count"] == len(record["findings"])
    assert record["fallback_reason"]
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is True


def test_the_runner_explains_the_findings_policy_exit_code(monkeypatch):
    """
    Without the flag of the repository the CLI applies its findings policy: the
    code 255 then belongs to a finished analysis and is classified as such.
    """
    fake = _FakeSlither(returncode=SLITHER_ABORT_EXIT_CODE, report=_report())

    def _run(cmd: list, *, cwd: str, env: dict, timeout: int) -> CappedProcessResult:
        if cmd[-1] == "--version":
            return CappedProcessResult(0, "slither-analyzer 0.11.6", "")
        if "--json" in cmd:
            json_out = cmd[cmd.index("--json") + 1]
            with open(json_out, "w", encoding="utf-8") as handle:
                json.dump(_report(), handle)
        return CappedProcessResult(SLITHER_ABORT_EXIT_CODE, "", "")

    # The first call refuses the flag of the repository, the second one runs
    # without it - the findings policy of the CLI is then in effect.
    def _refuse_flag(cmd: list, *, cwd: str, env: dict, timeout: int) -> CappedProcessResult:
        if "--fail-none" in cmd:
            return CappedProcessResult(
                2, "", "slither: error: unrecognized arguments: --fail-none", False
            )
        return _run(cmd, cwd=cwd, env=env, timeout=timeout)

    monkeypatch.setattr(runner_module, "run_subprocess_capped", _refuse_flag)

    record = run_slither_analysis_detailed(_target())

    assert record["analysis_status"] == STATUS_COMPLETED
    assert record["mode"] == MODE_SLITHER
    assert record["exit_code_disposition"] == DISPOSITION_FINDINGS_POLICY
    assert record["slither_exit_code"] == SLITHER_ABORT_EXIT_CODE
    assert "--fail-none" not in record["slither_argv"]
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is True


def test_the_runner_reports_a_failed_launch_as_a_fallback(monkeypatch):
    fake = _FakeSlither(
        returncode=127,
        write_report=False,
        stderr="slither: command not found",
    )
    monkeypatch.setattr(runner_module, "run_subprocess_capped", fake)

    record = run_slither_analysis_detailed(_target())

    assert record["analysis_status"] == STATUS_FALLBACK
    assert record["mode"] == MODE_FALLBACK
    assert record["exit_code_disposition"] == DISPOSITION_NO_REPORT
    assert record["slither_report_present"] is False
    assert record["slither_report_valid"] is False
    assert record["fallback_reason"]
    assert "command not found" in record["fallback_reason"]
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is True


def test_the_runner_reports_a_broken_report_as_a_partial_run(monkeypatch):
    fake = _FakeSlither(returncode=1, raw_report='{"success": true, "resu')
    monkeypatch.setattr(runner_module, "run_subprocess_capped", fake)

    record = run_slither_analysis_detailed(_target())

    assert record["analysis_status"] == STATUS_PARTIAL
    assert record["mode"] == MODE_FALLBACK
    assert record["exit_code_disposition"] == DISPOSITION_UNPARSABLE_REPORT
    assert record["slither_report_present"] is True
    assert record["slither_report_valid"] is False
    assert static_analysis_evidence_is_consistent(_as_evidence(record)) is True


def test_the_runner_keeps_the_output_of_the_detector_in_the_record(monkeypatch):
    """The stdout and the stderr of the run are part of the evidence."""
    fake = _FakeSlither(
        returncode=0,
        report=_report(),
        stdout="Vault analyzed (1 contracts with 40 detectors), 2 result(s) found",
        stderr="INFO: Detectors: 40",
    )
    monkeypatch.setattr(runner_module, "run_subprocess_capped", fake)

    record = run_slither_analysis_detailed(_target())

    assert "2 result(s) found" in record["slither_stdout_tail"]
    assert "Detectors: 40" in record["slither_stderr_tail"]
    assert record["slither_timed_out"] is False


def test_an_unsafe_target_is_refused_without_any_analysis(monkeypatch):
    fake = _FakeSlither(returncode=0, report=_report())
    monkeypatch.setattr(runner_module, "run_subprocess_capped", fake)

    target = TargetProgram(name="../etc/passwd", source_code="contract X {}")
    record = run_slither_analysis_detailed(target)

    assert record["mode"] == MODE_REFUSED
    assert record["analysis_status"] == STATUS_UNAVAILABLE
    assert record["exit_code_disposition"] == DISPOSITION_NOT_RUN
    assert fake.calls == []


# ---------------------------------------------------------------------------
# 4. Strict validation of the Slither JSON contract
# ---------------------------------------------------------------------------


def test_a_report_without_the_required_success_field_is_rejected():
    report = _report()
    del report["success"]
    outcome = classify_slither_outcome(
        exit_code=0, report=report, report_present=True, report_parsable=True
    )
    assert outcome["report_valid"] is False
    assert outcome["report_success"] is None
    assert outcome["analysis_status"] == STATUS_PARTIAL
    assert outcome["analysis_mode"] == MODE_FALLBACK


def test_a_report_with_non_boolean_success_is_rejected():
    report = _report()
    report["success"] = "true"
    outcome = classify_slither_outcome(
        exit_code=0, report=report, report_present=True, report_parsable=True
    )
    assert outcome["report_valid"] is False
    assert outcome["analysis_status"] == STATUS_PARTIAL


def test_a_report_with_missing_detectors_is_rejected():
    report = _report()
    del report["results"]["detectors"]
    outcome = classify_slither_outcome(
        exit_code=0, report=report, report_present=True, report_parsable=True
    )
    assert outcome["report_valid"] is False
    assert outcome["analysis_status"] == STATUS_PARTIAL


@pytest.mark.parametrize("detectors", [None, {}, ["not-an-object"], [None]])
def test_a_report_with_malformed_detectors_is_rejected(detectors):
    report = _report()
    report["results"]["detectors"] = detectors
    outcome = classify_slither_outcome(
        exit_code=0, report=report, report_present=True, report_parsable=True
    )
    assert outcome["report_valid"] is False
    assert outcome["analysis_status"] == STATUS_PARTIAL


def test_evidence_gate_rejects_completed_analysis_without_success_true():
    record = _record(slither_report_success=None)
    assert static_analysis_evidence_is_consistent(record) is False
