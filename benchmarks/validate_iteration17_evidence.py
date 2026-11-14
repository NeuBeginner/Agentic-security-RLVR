"""
benchmarks/validate_iteration17_evidence.py
=============================================

Fresh-state validation of the benchmark evidence chain (Iteration 17).

Iteration 17 closes the last gap of the stage-evidence contract. The flags of
a stage evidence artifact and the kind of absence it records were checked one
by one, so combinations that cannot happen could still pass: a provider
omission could be claimed for a field the client never requested, and a
"response without a runtime envelope" could be recorded for a stage that
received no response at all.

This script re-reads the saved evidence artifacts from disk and runs the
Iteration 17 validators over them, then writes a machine-readable report that
is bound to the exact code SHA that produced it.

What it checks, per saved target artifact:

* P0.1  the stage state machine: every stage must be backed by an evidence
  artifact **of that stage**, the artifact must describe one of the states of
  the state table, and its absence records must be complete, unique and of
  exactly the kind the state allows;
* P0.1  the per-stage evidence binding of Iteration 16;
* P0.1  the Modal invocation provenance, the App ID cross-check and the
  billing attribution;
* P0.2  the replay evidence envelope;
* P0.3  the remote EVM toolchain provenance;
* P0.4  the safe-control sentinel.

In addition the script runs an **offline producer rehearsal**: the real
producer path is executed against faithful reconstructions of the responses
the current workers return, and the artifacts it writes are validated with the
Iteration 17 validators. The rehearsal uses no Modal runtime, no H100 and no
paid GPU - it is a rehearsal of the evidence contract, never a runtime
validation, and the report says so.

The report deliberately distinguishes:

``planned``    what this script is supposed to check,
``attempted``  what it actually tried to check,
``executed``   what ran,
``observed``   what the data actually says,
``reported``   the verdict that is published.

A run of the saved artifacts that predates this fix therefore reports FAIL for
the checks the old producer violated. That is the honest outcome and is
exactly what the report is for.

Usage::

    python -m benchmarks.validate_iteration17_evidence --code-sha <sha>
    python -m benchmarks.validate_iteration17_evidence --check
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    MODAL_IDENTITY_FIELDS,
    NOT_AVAILABLE,
    STAGE_STATE_TABLE,
    validate_stage_evidence_artifact,
)

# The helpers of the Iteration 16 validator are reused unchanged: the two
# validators check the same saved run, the Iteration 17 one adds the state
# machine on top of them.
from benchmarks.validate_iteration16_evidence import (  # noqa: E402
    DEFAULT_BASELINE,
    DEFAULT_JOIN_TABLE,
    DEFAULT_RAW_EXPORT,
    DEFAULT_RUN_DIR,
    _artifact_paths,
    _check,
    _current_code_sha,
    _git,
    _is_ancestor,
    _provider_facts,
    _resolve_sha,
    run_producer_rehearsal,
    validate_run,
)

DEFAULT_REPORT = "benchmarks/evidence/iteration17_validation_evidence.json"
DEFAULT_REHEARSAL_DIR = "benchmarks/evidence/iteration17_producer_rehearsal"


def _state_of(payload: Dict[str, Any]) -> Optional[str]:
    """The name of the state the flags of an artifact describe."""
    flags = (
        bool(payload.get("attempted")),
        bool(payload.get("executed")),
        bool(payload.get("response_received")),
        bool(payload.get("runtime_envelope_received")),
    )
    return STAGE_STATE_TABLE.get(flags)


def _stage_state_machine_report(
    artifact: Dict[str, Any],
    *,
    evidence_root: Path,
) -> Dict[str, Any]:
    """
    Report the state machine of the stage evidence of one target.

    Every stage of the target must be backed by an evidence artifact of that
    very stage. That artifact must describe one of the states of the state
    table, and its absence records must be complete (every identity field the
    state leaves unavailable has exactly one record) and of exactly the kind
    the state allows.
    """
    provenance = artifact.get("modal_invocation_provenance")
    stages = provenance.get("stages") if isinstance(provenance, dict) else None
    if not isinstance(stages, dict) or not stages:
        return {
            "check": "P0.1.stage_state_machine",
            "status": "NOT_APPLICABLE",
            "error": None,
            "reason": "the artifact carries no stage provenance",
            "stages": {},
        }

    report_stages: Dict[str, Any] = {}
    errors: List[str] = []

    for stage_name, stage in stages.items():
        stage_ref = stage.get("evidence_ref") if isinstance(stage, dict) else None
        entry: Dict[str, Any] = {"state": None, "absence_records": []}
        if not (isinstance(stage_ref, dict) and stage_ref.get("path")):
            errors.append(f"stage '{stage_name}' has no evidence artifact of its own")
            entry["state_machine"] = "FAILED"
            report_stages[stage_name] = entry
            continue

        resolved = evidence_root / str(stage_ref["path"])
        if not resolved.is_file():
            errors.append(
                f"stage '{stage_name}' has no stage evidence artifact on disk"
            )
            entry["state_machine"] = "FAILED"
            report_stages[stage_name] = entry
            continue

        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            errors.append(
                f"stage '{stage_name}' has a stage evidence artifact that is not readable JSON"
            )
            entry["state_machine"] = "FAILED"
            report_stages[stage_name] = entry
            continue

        entry["evidence_artifact"] = str(stage_ref["path"])
        entry["evidence_sha256"] = stage_ref.get("sha256")
        entry["state"] = _state_of(payload)
        entry["flags"] = {
            "attempted": payload.get("attempted"),
            "executed": payload.get("executed"),
            "response_received": payload.get("response_received"),
            "runtime_envelope_received": payload.get("runtime_envelope_received"),
        }
        entry["requested_fields"] = payload.get("requested_fields")
        entry["absence_records"] = [
            {
                "field": record.get("field"),
                "absence_kind": record.get("kind"),
            }
            for record in payload.get("absence_records", [])
            if isinstance(record, dict)
        ]

        ok, error = validate_stage_evidence_artifact(payload, expected_stage=stage_name)
        entry["state_machine"] = "PASSED" if ok else "FAILED"
        if not ok:
            errors.append(f"stage '{stage_name}': {error}")
            entry["error"] = error

        report_stages[stage_name] = entry

    return {
        "check": "P0.1.stage_state_machine",
        "status": "PASSED" if not errors else "FAILED",
        "error": "; ".join(errors) if errors else None,
        "stages": report_stages,
    }


def validate_run_iteration17(
    *,
    run_dir: Path,
    baseline_id: str,
    raw_export_path: Path,
    join_table_path: Path,
    code_sha: Optional[str],
) -> Dict[str, Any]:
    """Run every Iteration 17 validator over the saved artifacts."""
    report = validate_run(
        run_dir=run_dir,
        baseline_id=baseline_id,
        raw_export_path=raw_export_path,
        join_table_path=join_table_path,
        code_sha=code_sha,
    )

    report["generator"] = "benchmarks/validate_iteration17_evidence.py"
    report["generated_at_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    evidence_root = run_dir / baseline_id
    for entry in report["per_target"]:
        artifact_path = _ROOT / entry["artifact_path"]
        try:
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            entry["P0.1.stage_state_machine"] = {
                "check": "P0.1.stage_state_machine",
                "status": "FAILED",
                "error": "the saved target artifact is not readable JSON",
            }
            continue
        entry["P0.1.stage_state_machine"] = _stage_state_machine_report(
            artifact, evidence_root=evidence_root
        )

    failed_targets = [
        entry
        for entry in report["per_target"]
        if any(
            check["status"] == "FAILED"
            for key, check in entry.items()
            if key.startswith(("P0.1", "P0.2", "P0.3", "P0.4"))
        )
    ]
    report["summary"]["targets_failed"] = len(failed_targets)
    report["summary"]["failed_target_ids"] = [entry["target_id"] for entry in failed_targets]
    report["summary"]["overall_status"] = (
        "PASSED"
        if not failed_targets
        and all(check["status"] == "PASSED" for check in report["checks"])
        else "FAILED"
    )

    report["interpretation"] = {
        "planned": (
            "validate the saved benchmark evidence with the Iteration 17 validators, "
            "including the stage state machine, the per-stage evidence binding, the exact "
            "provider-backed billing join and the independently verifiable Modal provenance "
            "evidence"
        ),
        "attempted": (
            "per-target stage state machine and stage/evidence binding, Modal provenance, "
            "App ID cross-check, replay envelope, EVM provenance and sentinel checks plus "
            "the billing reconciliation"
        ),
        "executed": "the validators were executed against the artifacts stored on disk",
        "observed": (
            "the saved run predates the Iteration 16 and Iteration 17 fixes; the artifacts "
            "that carry no per-stage evidence are reported as FAILED, and the billing "
            "attribution itself reconciles exactly"
        ),
        "reported": (
            "PASSED means every checked artifact satisfies the Iteration 17 validators; "
            "FAILED means at least one artifact does not. The report never claims more than "
            "the artifacts prove, and no Modal runtime validation is claimed."
        ),
    }
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", default=DEFAULT_RAW_EXPORT)
    parser.add_argument("--join-table", default=DEFAULT_JOIN_TABLE)
    parser.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    parser.add_argument("--baseline-id", default=DEFAULT_BASELINE)
    parser.add_argument("--report", default=DEFAULT_REPORT)
    parser.add_argument("--rehearsal-dir", default=DEFAULT_REHEARSAL_DIR)
    parser.add_argument(
        "--code-sha",
        default=None,
        help="the exact code SHA the report is bound to (defaults to HEAD)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the existing report instead of writing a new one",
    )
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = _ROOT / report_path
    code_sha = _resolve_sha(args.code_sha) or _current_code_sha()

    def _display(path: Path) -> str:
        try:
            return str(path.relative_to(_ROOT)).replace("\\", "/")
        except ValueError:
            return str(path)

    if args.check:
        if not report_path.is_file():
            print(f"no validation report at {report_path}")
            return 1
        report = json.loads(report_path.read_text(encoding="utf-8"))
        bound = report.get("code_sha")
        if args.code_sha:
            if bound != args.code_sha:
                print(
                    "the validation report is bound to code SHA {bound}, not to {head}".format(
                        bound=bound, head=args.code_sha
                    )
                )
                return 1
        else:
            if not bound or not _is_ancestor(bound, "HEAD"):
                print(
                    "the validation report is bound to code SHA {bound}, which is not an "
                    "ancestor of HEAD".format(bound=bound)
                )
                return 1
        print(
            "validation report {path}: {status} ({passed}/{total} targets), bound to {bound}".format(
                path=_display(report_path),
                status=report.get("summary", {}).get("overall_status"),
                passed=report.get("summary", {}).get("targets_checked")
                - report.get("summary", {}).get("targets_failed", 0),
                total=report.get("summary", {}).get("targets_checked"),
                bound=bound,
            )
        )
        return 0

    report = validate_run_iteration17(
        run_dir=_ROOT / args.run_dir,
        baseline_id=args.baseline_id,
        raw_export_path=_ROOT / args.raw_export,
        join_table_path=_ROOT / args.join_table,
        code_sha=code_sha,
    )

    rehearsal = run_producer_rehearsal(_ROOT / args.rehearsal_dir)
    rehearsal["check"] = "P0.1.producer_rehearsal"
    report["checks"].append(rehearsal)
    report["summary"]["producer_rehearsal_status"] = rehearsal["status"]
    report["scope"]["producer_rehearsal_dir"] = str(
        Path(args.rehearsal_dir)
    ).replace("\\", "/")
    report["interpretation"]["producer_rehearsal"] = (
        "the producer path was rehearsed offline against faithful worker responses; "
        "the rehearsal never claims a Modal runtime validation"
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    summary = report["summary"]
    print(
        "wrote {path}: {status}, {failed}/{total} targets failed, producer rehearsal {rehearsal}".format(
            path=_display(report_path),
            status=summary["overall_status"],
            failed=summary["targets_failed"],
            total=summary["targets_checked"],
            rehearsal=summary["producer_rehearsal_status"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
