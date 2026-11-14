"""
core/slither_status.py
=======================

The unambiguous classification of **one** Slither invocation.

Why this module exists
----------------------
The repository used to decide that "Slither ran" by the mere presence of the JSON
report that Slither writes. That is wrong, and the acceptance evidence of the
CPU-only audit service proved it: Slither 0.11.6 exited with the code ``255``
while the report was complete and correct.

The cause is documented in the Slither CLI itself (``slither/__main__.py`` of the
tag ``0.11.6``)::

    fail_on = FailOnLevel(args.fail_on)            # the default is PEDANTIC
    if fail_on == FailOnLevel.PEDANTIC:
        fail_on_detection = bool(results_detectors)
    ...
    if output_error or fail_on_detection:
        sys.exit(-1)                                # the shell reports this as 255

``sys.exit(-1)`` is the exit code of the **findings policy** of the CLI: with the
default ``--fail-on pedantic`` Slither leaves with a non-zero code as soon as it
found anything - and it writes the JSON report *before* that exit. The very same
exit code is used when the analysis itself failed (``output_error`` is set and the
report states ``"success": false``). The exit code alone therefore says nothing
about whether the analysis succeeded, and the presence of a report with findings
says nothing either.

This module turns the observable facts of one invocation into exactly one status:

``completed``
    Slither really analysed the target and the report is valid.
``partial``
    Slither wrote a report but did not finish the analysis: the report states the
    failure, the report is unusable, or the exit code has no explanation.
``fallback``
    Slither produced no usable report at all - the deterministic heuristics of
    this repository are used instead.
``unavailable``
    The static analysis stage did not run at all.

The findings of a partial run are **never** presented as the result of an
analysis: the deterministic fallback heuristics of the repository take over and
the reason is part of the record. A report with findings is evidence of a
detector run, not evidence of a successful analysis.

The module has no dependency at all - it is pure data in, pure data out - so the
sandbox that runs Slither, the acceptance gate of the evidence and the offline
tests all judge a run by exactly the same rules.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

#: The exit code the shell reports for ``sys.exit(-1)``, which is what the Slither
#: CLI uses both for its findings policy and for an aborted analysis.
SLITHER_ABORT_EXIT_CODE = 255

# ---------------------------------------------------------------------------
# The status of the analysis
# ---------------------------------------------------------------------------

#: Slither analysed the target and the report is valid.
STATUS_COMPLETED = "completed"
#: Slither wrote a report but did not finish the analysis.
STATUS_PARTIAL = "partial"
#: Slither produced no usable report; the heuristics of the repository were used.
STATUS_FALLBACK = "fallback"
#: The static analysis stage did not run.
STATUS_UNAVAILABLE = "unavailable"

ANALYSIS_STATUSES = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_FALLBACK,
    STATUS_UNAVAILABLE,
)

# ---------------------------------------------------------------------------
# The provenance of the findings
# ---------------------------------------------------------------------------

#: The findings are the output of the real Slither detectors.
MODE_SLITHER = "slither"
#: The findings are the deterministic fallback heuristics of this repository.
MODE_FALLBACK = "fallback_heuristics"
#: There are no findings at all.
MODE_UNAVAILABLE = "unavailable"
#: The target was refused before any analysis was started.
MODE_REFUSED = "refused"

ANALYSIS_MODES = (MODE_SLITHER, MODE_FALLBACK, MODE_UNAVAILABLE, MODE_REFUSED)

# ---------------------------------------------------------------------------
# The disposition of the exit code
# ---------------------------------------------------------------------------

#: The process left with the code 0.
DISPOSITION_CLEAN_EXIT = "clean_exit"
#: The process left with the code 255 because it found something and the findings
#: policy of the CLI was in effect. This is the documented cause of that code.
DISPOSITION_FINDINGS_POLICY = "slither_findings_fail_on_policy"
#: The report of the process states that the analysis failed.
DISPOSITION_ANALYSIS_ERROR = "analysis_error"
#: The process left with a non-zero code that has no explanation.
DISPOSITION_UNEXPLAINED_EXIT = "unexplained_exit_code"
#: The process wrote no report at all.
DISPOSITION_NO_REPORT = "no_valid_report"
#: The process wrote a report that could not be parsed.
DISPOSITION_UNPARSABLE_REPORT = "unparsable_report"
#: The process did not finish within its timeout.
DISPOSITION_TIMEOUT = "timed_out"
#: The process was never started.
DISPOSITION_NOT_RUN = "not_run"

#: The dispositions that belong to a partial analysis.
PARTIAL_DISPOSITIONS = (
    DISPOSITION_ANALYSIS_ERROR,
    DISPOSITION_UNPARSABLE_REPORT,
    DISPOSITION_UNEXPLAINED_EXIT,
    DISPOSITION_TIMEOUT,
)

#: The dispositions that belong to a plain fallback.
FALLBACK_DISPOSITIONS = (
    DISPOSITION_NO_REPORT,
    DISPOSITION_TIMEOUT,
)


def classify_slither_outcome(
    *,
    exit_code: Optional[int],
    report: Optional[Dict[str, Any]],
    report_present: bool,
    report_parsable: bool,
    timed_out: bool = False,
    findings_policy_disabled: bool = True,
) -> Dict[str, Any]:
    """
    Classify one Slither invocation into exactly one analysis status.

    The classification uses only observable facts:

    * ``exit_code`` - the exit code of the Slither process (``None`` if it never ran);
    * ``report`` - the parsed JSON report of Slither, if there is one;
    * ``report_present`` - whether a report file was written at all;
    * ``report_parsable`` - whether that file could be parsed into a JSON object;
    * ``timed_out`` - whether the process had to be killed by the timeout;
    * ``findings_policy_disabled`` - whether the invocation disabled the findings
      policy of the Slither CLI (``--fail-none``). Only if the policy was **not**
      disabled can the code 255 be attributed to it.

    The result carries the status, the provenance of the findings, the disposition
    of the exit code and the facts the disposition was derived from.
    """
    parsed = isinstance(report, dict)
    report_success: Optional[bool] = None
    report_error: Optional[str] = None
    detectors: List[Dict[str, Any]] = []

    # Slither's JSON contract is explicit: success must be a boolean, error
    # must be null or a string, and results.detectors must be a list of objects.
    # Do not silently coerce missing/null/malformed fields into an empty report.
    report_valid = False
    if parsed:
        raw_success = report.get("success")
        raw_error = report.get("error")
        raw_results = report.get("results")
        raw_detectors = raw_results.get("detectors") if isinstance(raw_results, dict) else None

        report_success = raw_success if isinstance(raw_success, bool) else None
        report_error = raw_error if isinstance(raw_error, str) else None
        report_valid = (
            isinstance(raw_success, bool)
            and (raw_error is None or isinstance(raw_error, str))
            and isinstance(raw_results, dict)
            and isinstance(raw_detectors, list)
            and all(isinstance(item, dict) for item in raw_detectors)
        )
        if report_valid:
            detectors = raw_detectors

    has_findings = bool(detectors)

    if timed_out:
        # A killed process never analysed the target completely.
        status = STATUS_PARTIAL if report_present else STATUS_FALLBACK
        disposition = DISPOSITION_TIMEOUT
    elif not report_present:
        status = STATUS_FALLBACK
        disposition = DISPOSITION_NO_REPORT
    elif not report_parsable or not report_valid:
        status = STATUS_PARTIAL
        disposition = DISPOSITION_UNPARSABLE_REPORT
    elif report_success is not True:
        status = STATUS_PARTIAL
        disposition = DISPOSITION_ANALYSIS_ERROR
    elif exit_code == 0:
        status = STATUS_COMPLETED
        disposition = DISPOSITION_CLEAN_EXIT
    elif (
        exit_code == SLITHER_ABORT_EXIT_CODE
        and has_findings
        and not findings_policy_disabled
    ):
        # The only non-zero code that a valid report may carry: the findings policy
        # of the CLI, which leaves with ``sys.exit(-1)`` as soon as it found
        # something. The report is written before that exit.
        status = STATUS_COMPLETED
        disposition = DISPOSITION_FINDINGS_POLICY
    else:
        status = STATUS_PARTIAL
        disposition = DISPOSITION_UNEXPLAINED_EXIT

    if status == STATUS_COMPLETED:
        mode = MODE_SLITHER
    elif status == STATUS_UNAVAILABLE:
        mode = MODE_UNAVAILABLE
    else:
        # The findings of a partial run are not the findings of the report: the
        # deterministic heuristics of the repository take over.
        mode = MODE_FALLBACK

    return {
        "analysis_status": status,
        "analysis_mode": mode,
        "exit_code_disposition": disposition,
        "report_valid": report_valid,
        "report_success": report_success,
        "report_error": report_error,
        "detector_count": len(detectors),
        "detectors": detectors,
        "has_findings": has_findings,
    }


def static_analysis_evidence_is_consistent(record: Dict[str, Any]) -> bool:
    """
    Do the exit code, the analysis status, the validity of the report and the
    fallback flag of one static analysis record tell the same story?

    This is the single rule that the acceptance gate of the evidence and the
    offline tests share: a record that contradicts itself is not accepted, no
    matter how many findings it carries.
    """
    if not isinstance(record, dict):
        return False

    mode = record.get("analysis_mode")
    status = record.get("analysis_status")
    exit_code = record.get("slither_exit_code")
    disposition = record.get("exit_code_disposition")
    report_valid = record.get("slither_report_valid")
    report_success = record.get("slither_report_success")
    fallback_reason = record.get("fallback_reason")

    if mode not in ANALYSIS_MODES or status not in ANALYSIS_STATUSES:
        return False

    # 1. Only a completed analysis may claim the real Slither, and only the real
    #    Slither may be completed.
    if mode == MODE_SLITHER and status != STATUS_COMPLETED:
        return False
    if status == STATUS_COMPLETED and mode != MODE_SLITHER:
        return False

    # 2. A completed analysis needs a valid report that does not state a failure,
    #    no fallback, and an exit code that is explained.
    if status == STATUS_COMPLETED:
        if report_valid is not True or report_success is not True:
            return False
        if fallback_reason is not None:
            return False
        if exit_code == 0:
            return disposition == DISPOSITION_CLEAN_EXIT
        if exit_code == SLITHER_ABORT_EXIT_CODE:
            # The only non-zero code that is accepted next to a valid report is the
            # documented findings policy of the Slither CLI.
            return disposition == DISPOSITION_FINDINGS_POLICY
        return False

    # 3. A fallback always names its reason and never claims the real Slither.
    if mode == MODE_FALLBACK:
        if not fallback_reason:
            return False
        if status == STATUS_PARTIAL:
            return disposition in PARTIAL_DISPOSITIONS
        if status == STATUS_FALLBACK:
            return disposition in FALLBACK_DISPOSITIONS and report_valid is not True
        return False

    # 4. An unavailable stage explains itself.
    return status == STATUS_UNAVAILABLE and disposition == DISPOSITION_NOT_RUN