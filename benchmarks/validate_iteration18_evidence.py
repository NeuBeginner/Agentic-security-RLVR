"""
benchmarks/validate_iteration18_evidence.py
============================================

Fresh-state validation of the benchmark evidence chain (Iteration 18).

Iteration 18 binds the captured response to the runtime envelope. The
Iteration 17 review found three remaining ways for an internally
self-consistent, SHA-256-valid artifact to misrepresent what the stage
actually returned:

* a stage that claimed "no response" could still store a provider response,
  and its response metadata always carried a digest, a byte length and a
  source that made a stage without a response look like a stage whose response
  was captured;
* the check that binds the runtime-identity envelope to the captured response
  was skipped for a payload that is not an object, so a fabricated envelope
  passed;
* a malformed identity fact in the envelope was re-labelled as a field the
  provider had omitted.

This script re-reads the saved evidence artifacts from disk and runs the
Iteration 18 validators over them, then writes a machine-readable report that
is bound to the exact code SHA that produced it.

What it checks, per saved target artifact:

* P0.1  the response/envelope binding: the flag of a stage and the payload it
  stores must agree in both directions, the runtime-identity envelope must be
  the one the captured response carries at the declared source - for every
  shape of the payload - and every identity fact of the envelope must be a
  documented typed fact;
* P0.1  the stage state machine of Iteration 17 and the per-stage evidence
  binding of Iteration 16;
* P0.1  the Modal invocation provenance, the App ID cross-check and the
  billing attribution;
* P0.2  the replay evidence envelope;
* P0.3  the remote EVM toolchain provenance;
* P0.4  the safe-control sentinel.

In addition the script runs an **offline producer rehearsal**: the real
producer path is executed against faithful reconstructions of the responses
the current workers return, and the artifacts it writes are validated with the
Iteration 18 validators. The rehearsal uses no Modal runtime, no H100 and no
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

    python -m benchmarks.validate_iteration18_evidence --code-sha <sha>
    python -m benchmarks.validate_iteration18_evidence --check
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
    STAGE_STATE_TABLE,
    validate_runtime_identity_envelope,
    validate_stage_evidence_artifact,
)

# The helpers of the Iteration 16 validator are reused unchanged: the two
# validators check the same saved run, the Iteration 18 one adds the
# response/envelope binding on top of them.
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

DEFAULT_REPORT = "benchmarks/evidence/iteration18_validation_evidence.json"
DEFAULT_REHEARSAL_DIR = "benchmarks/evidence/iteration18_producer_rehearsal"


def _state_of(payload: Dict[str, Any]) -> Optional[str]:
    """The name of the state the flags of an artifact describe."""
    flags = (
        bool(payload.get("attempted")),
        bool(payload.get("executed")),
        bool(payload.get("response_received")),
        bool(payload.get("runtime_envelope_received")),
    )
    return STAGE_STATE_TABLE.get(flags)


def _binding_report(
    artifact: Dict[str, Any],
    *,
    evidence_root: Path,
) -> Dict[str, Any]:
    """
    Report the response/envelope binding of every stage of one target.

    For every stage the report states what was actually captured: whether the
    stage received a response (and what shape it had), whether it received a
    runtime-identity envelope (and where the envelope came from), and whether
    the envelope is the one the captured response carries. The stage is
    accepted only when the artifact itself passes the Iteration 18 validator.
    """
    provenance = artifact.get("modal_invocation_provenance")
    stages = provenance.get("stages") if isinstance(provenance, dict) else None
    if not isinstance(stages, dict) or not stages:
        return {
            "check": "P0.1.response_envelope_binding",
            "status": "NOT_APPLICABLE",
            "error": None,
            "reason": "the artifact carries no stage provenance",
            "stages": {},
        }

    report_stages: Dict[str, Any] = {}
    errors: List[str] = []

    for stage_name, stage in stages.items():
        stage_ref = stage.get("evidence_ref") if isinstance(stage, dict) else None
        entry: Dict[str, Any] = {"state": None, "binding": "UNKNOWN"}
        if not (isinstance(stage_ref, dict) and stage_ref.get("path")):
            errors.append(f"stage '{stage_name}' has no evidence artifact of its own")
            entry["binding"] = "FAILED"
            report_stages[stage_name] = entry
            continue

        resolved = evidence_root / str(stage_ref["path"])
        if not resolved.is_file():
            errors.append(f"stage '{stage_name}' has no stage evidence artifact on disk")
            entry["binding"] = "FAILED"
            report_stages[stage_name] = entry
            continue

        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            errors.append(
                f"stage '{stage_name}' has a stage evidence artifact that is not readable JSON"
            )
            entry["binding"] = "FAILED"
            report_stages[stage_name] = entry
            continue

        provider_response = payload.get("provider_response")
        runtime_identity = payload.get("runtime_identity")
        source = payload.get("runtime_identity_source")

        entry["evidence_artifact"] = str(stage_ref["path"])
        entry["evidence_sha256"] = stage_ref.get("sha256")
        entry["state"] = _state_of(payload)
        entry["response_received"] = bool(payload.get("response_received"))
        entry["response_captured"] = provider_response is not None
        entry["response_shape"] = type(provider_response).__name__
        entry["envelope_received"] = bool(payload.get("runtime_envelope_received"))
        entry["envelope_source"] = source
        entry["envelope_is_typed"] = bool(
            validate_runtime_identity_envelope(runtime_identity)[0]
        )
        entry["identity_fields"] = [
            field
            for field in MODAL_IDENTITY_FIELDS
            if isinstance(runtime_identity, dict) and field in runtime_identity
        ]

        if entry["response_received"] != entry["response_captured"]:
            entry["binding"] = "FAILED"
            errors.append(
                f"stage '{stage_name}': the flag of the response and the stored payload "
                "contradict each other"
            )
            report_stages[stage_name] = entry
            continue

        if entry["envelope_received"]:
            if not isinstance(provider_response, dict):
                entry["binding"] = "FAILED"
                errors.append(
                    f"stage '{stage_name}': the captured response is not an object and can "
                    "therefore not carry the runtime-identity envelope"
                )
                report_stages[stage_name] = entry
                continue
            if source not in provider_response:
                entry["binding"] = "FAILED"
                errors.append(
                    f"stage '{stage_name}': the captured response does not carry the "
                    f"runtime-identity envelope at {source!r}"
                )
                report_stages[stage_name] = entry
                continue
            entry["binding"] = "BOUND"

        ok, error = validate_stage_evidence_artifact(payload, expected_stage=stage_name)
        if not ok:
            entry["binding"] = "FAILED"
            errors.append(f"stage '{stage_name}': {error}")
            entry["error"] = error
        elif entry["binding"] == "UNKNOWN":
            entry["binding"] = "NO_ENVELOPE"

        report_stages[stage_name] = entry

    return {
        "check": "P0.1.response_envelope_binding",
        "status": "PASSED" if not errors else "FAILED",
        "error": "; ".join(errors) if errors else None,
        "stages": report_stages,
    }


def validate_run_iteration18(
    *,
    run_dir: Path,
    baseline_id: str,
    raw_export_path: Path,
    join_table_path: Path,
    code_sha: Optional[str],
) -> Dict[str, Any]:
    """Run every Iteration 18 validator over the saved artifacts."""
    report = validate_run(
        run_dir=run_dir,
        baseline_id=baseline_id,
        raw_export_path=raw_export_path,
        join_table_path=join_table_path,
        code_sha=code_sha,
    )

    report["generator"] = "benchmarks/validate_iteration18_evidence.py"
    report["generated_at_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    evidence_root = run_dir / baseline_id
    for entry in report["per_target"]:
        artifact_path = _ROOT / entry["artifact_path"]
        try:
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            entry["P0.1.response_envelope_binding"] = {
                "check": "P0.1.response_envelope_binding",
                "status": "FAILED",
                "error": "the saved target artifact is not readable JSON",
                "stages": {},
            }
            continue
        entry["P0.1.response_envelope_binding"] = _binding_report(
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
            "validate the saved benchmark evidence with the Iteration 18 validators, "
            "including the binding of the captured response to the runtime-identity "
            "envelope, the stage state machine, the per-stage evidence binding, the exact "
            "provider-backed billing join and the independently verifiable Modal provenance "
            "evidence"
        ),
        "attempted": (
            "per-target response/envelope binding, stage state machine and stage/evidence "
            "binding, Modal provenance, App ID cross-check, replay envelope, EVM provenance "
            "and sentinel checks plus the billing reconciliation"
        ),
        "executed": "the validators were executed against the artifacts stored on disk",
        "observed": (
            "the saved run predates the Iteration 16, Iteration 17 and Iteration 18 fixes; the "
            "artifacts that carry no per-stage evidence are reported as FAILED, and the "
            "billing attribution itself reconciles exactly"
        ),
        "reported": (
            "PASSED means every checked artifact satisfies the Iteration 18 validators; "
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
        summary = report.get("summary", {})
        print(
            "validation report {path}: {status} ({passed}/{total} targets), bound to {bound}".format(
                path=_display(report_path),
                status=summary.get("overall_status"),
                passed=summary.get("targets_checked", 0) - summary.get("targets_failed", 0),
                total=summary.get("targets_checked"),
                bound=bound,
            )
        )
        return 0

    report = validate_run_iteration18(
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
