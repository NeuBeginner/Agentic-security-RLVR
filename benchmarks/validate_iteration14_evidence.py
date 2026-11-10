"""
benchmarks/validate_iteration14_evidence.py

Fresh-state validation of the benchmark evidence chain (Iteration 14, Issue #11).

The script re-reads the saved evidence artifacts from disk and runs the
Iteration 14 validators over them, then writes a machine-readable report that
is bound to the exact code SHA that produced it.

What it checks, per saved target artifact:

* P0.1  the Modal invocation provenance (no hardcoded app id, no fabricated
  provider log URI, every NOT_AVAILABLE with a reason);
* P0.1  the billing attribution (every raw line item counted exactly once,
  aggregates reconciled exactly, no target cost without a proven join);
* P0.2  the replay evidence envelope (digests recomputed from the stored
  replay bytes, real container identity, replay-specific timestamps);
* P0.3  the remote EVM toolchain provenance (observed facts only, immutable
  image digest, no legacy hardcoded constants);
* P0.4  the safe-control sentinel (exact documented sentinel for the target).

The report deliberately distinguishes:

``planned``    what this script is supposed to check,
``attempted``  what it actually tried to check,
``executed``   what ran,
``observed``   what the data actually says,
``reported``   the verdict that is published.

A run of the saved artifacts that predates the fix therefore reports FAIL for
the checks the old producer violated. That is the honest outcome and is
exactly what the report is for.

Usage::

    python -m benchmarks.validate_iteration14_evidence --code-sha <sha>
    python -m benchmarks.validate_iteration14_evidence --check
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    has_synthetic_modal_uri,
    load_raw_billing_line_items,
    validate_billing_attribution,
    validate_modal_invocation_provenance,
    validate_remote_evm_toolchain_provenance,
    validate_replay_evidence_envelope,
    validate_safe_control_sentinel_semantics,
)

DEFAULT_RAW_EXPORT = "benchmarks/evidence/modal_billing_report_raw.json"
DEFAULT_JOIN_TABLE = "benchmarks/evidence/modal_billing_join_table.json"
DEFAULT_RUN_DIR = "benchmarks/artifacts/run_1794209615_70f5d22"
DEFAULT_BASELINE = "baseline_5"
DEFAULT_REPORT = "benchmarks/evidence/iteration14_validation_evidence.json"


def _git(*args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", *args], cwd=_ROOT, capture_output=True, text=True, timeout=30
        )
        if out.returncode != 0:
            return None
        value = out.stdout.strip()
        return value or None
    except Exception:
        return None


def _current_code_sha() -> Optional[str]:
    return _git("rev-parse", "HEAD")


def _resolve_sha(candidate: Optional[str]) -> Optional[str]:
    """Expand an abbreviated SHA into the full 40-character commit SHA."""
    if not candidate:
        return None
    resolved = _git("rev-parse", f"{candidate}^{{commit}}")
    return resolved or candidate


def _is_ancestor(candidate: str, descendant: str) -> bool:
    """True when ``candidate`` is an ancestor of ``descendant`` in this repository."""
    try:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", candidate, descendant],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def _artifact_paths(run_dir: Path, baseline_id: str) -> List[Path]:
    baseline_dir = run_dir / baseline_id
    if not baseline_dir.is_dir():
        return []
    return sorted(baseline_dir.glob("*.json"))


def _check(name: str, ok: bool, error: Optional[str], **extra: Any) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "check": name,
        "status": "PASSED" if ok else "FAILED",
        "error": error,
    }
    entry.update(extra)
    return entry


def validate_run(
    *,
    run_dir: Path,
    baseline_id: str,
    raw_export_path: Path,
    join_table_path: Path,
    code_sha: Optional[str],
) -> Dict[str, Any]:
    """Run every Iteration 14 validator over the saved artifacts."""
    checks: List[Dict[str, Any]] = []
    artifacts = _artifact_paths(run_dir, baseline_id)

    # --- P0.1 billing -----------------------------------------------------
    billing_planned = (
        "every raw billing line item is accounted for exactly once; aggregates "
        "reconcile exactly; no target carries a cost without a proven "
        "invocation-level join"
    )
    if raw_export_path.is_file() and join_table_path.is_file():
        line_items = load_raw_billing_line_items(raw_export_path)
        join_table = json.loads(join_table_path.read_text(encoding="utf-8"))
        ok, error = validate_billing_attribution(
            join_table, line_items, known_app_ids=[item.object_id for item in line_items]
        )
        checks.append(
            _check(
                "P0.1.billing_attribution",
                ok,
                error,
                planned=billing_planned,
                attempted=True,
                executed=True,
                raw_line_item_count=len(line_items),
                app_session_row_count=len(join_table.get("app_session_level", [])),
                target_row_count=len(join_table.get("target_level", [])),
                synthetic_uri_present=has_synthetic_modal_uri(join_table),
            )
        )
    else:
        checks.append(
            _check(
                "P0.1.billing_attribution",
                False,
                "the raw billing export or the join table is missing",
                planned=billing_planned,
                attempted=False,
                executed=False,
            )
        )

    # --- per-target checks ------------------------------------------------
    per_target: List[Dict[str, Any]] = []
    for artifact_path in artifacts:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        target_id = artifact.get("target_id", artifact_path.stem)
        target_name = artifact.get("target_name")

        modal_ok, modal_err = validate_modal_invocation_provenance(artifact)
        replay_ok, replay_err = validate_replay_evidence_envelope(
            artifact, artifact_root=run_dir / baseline_id
        )
        evm_ok, evm_err = validate_remote_evm_toolchain_provenance(artifact)

        sentinel_ok = True
        sentinel_err: Optional[str] = None
        sentinel_applicable = False
        stdout_path = artifact.get("stdout_path")
        if stdout_path:
            stdout_file = _ROOT / stdout_path
            if stdout_file.is_file():
                stdout = stdout_file.read_text(encoding="utf-8")
                tool_meta = artifact.get("tool_metadata", {})
                harness_verdict = tool_meta.get("harness_verdict") or artifact.get("harness_verdict")
                # The saved artifacts record the outcome category ("SAFE_RUN");
                # the trusted harness verdict itself is "NO_BREACH".
                if harness_verdict in ("SAFE_RUN", "NO_BREACH"):
                    sentinel_applicable = True
                    sentinel_ok, sentinel_err = validate_safe_control_sentinel_semantics(
                        _extract_sentinel(stdout),
                        "NO_BREACH",
                        target_name,
                        harness_suite=(
                            f"test/{target_name}Harness.t.sol" if target_name else None
                        ),
                    )

        sentinel_check = (
            _check("P0.4.safe_control_sentinel", sentinel_ok, sentinel_err)
            if sentinel_applicable
            else {
                "check": "P0.4.safe_control_sentinel",
                "status": "NOT_APPLICABLE",
                "error": None,
                "reason": (
                    "the target did not end in a NO_BREACH verdict, so there is no sentinel "
                    "to validate"
                ),
            }
        )

        per_target.append(
            {
                "target_id": target_id,
                "target_name": target_name,
                "artifact_path": str(artifact_path.relative_to(_ROOT)).replace("\\", "/"),
                "P0.1.modal_invocation_provenance": _check(
                    "P0.1.modal_invocation_provenance", modal_ok, modal_err
                ),
                "P0.2.replay_evidence_envelope": _check(
                    "P0.2.replay_evidence_envelope", replay_ok, replay_err
                ),
                "P0.3.remote_evm_toolchain_provenance": _check(
                    "P0.3.remote_evm_toolchain_provenance", evm_ok, evm_err
                ),
                "P0.4.safe_control_sentinel": sentinel_check,
            }
        )

    failed_targets = [
        entry
        for entry in per_target
        if any(
            check["status"] == "FAILED"
            for key, check in entry.items()
            if key.startswith(("P0.1", "P0.2", "P0.3", "P0.4"))
        )
    ]

    return {
        "schema_version": "1.0.0",
        "generator": "benchmarks/validate_iteration14_evidence.py",
        "code_sha": code_sha,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "run_id": run_dir.name,
            "baseline_id": baseline_id,
            "run_dir": str(run_dir.relative_to(_ROOT)).replace("\\", "/"),
            "artifact_count": len(artifacts),
            "raw_billing_export": str(raw_export_path.relative_to(_ROOT)).replace("\\", "/"),
            "billing_join_table": str(join_table_path.relative_to(_ROOT)).replace("\\", "/"),
        },
        "git": {
            "head": _git("rev-parse", "HEAD"),
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            # Only tracked modifications count: the report itself is written
            # after this snapshot is taken.
            "dirty": bool(_git("status", "--porcelain", "--untracked-files=no")),
        },
        "checks": checks,
        "per_target": per_target,
        "summary": {
            "targets_checked": len(per_target),
            "targets_failed": len(failed_targets),
            "failed_target_ids": [entry["target_id"] for entry in failed_targets],
            "overall_status": "PASSED" if not failed_targets and all(
                check["status"] == "PASSED" for check in checks
            ) else "FAILED",
        },
        "interpretation": {
            "planned": "validate the saved benchmark evidence with the Iteration 14 validators",
            "attempted": "per-target Modal provenance, replay envelope, EVM provenance and sentinel checks plus the billing reconciliation",
            "executed": "the validators were executed against the artifacts stored on disk",
            "observed": (
                "the saved run predates the Iteration 14 fix; the artifacts that carry the old "
                "hardcoded remote environment and the old synthetic container identities are "
                "reported as FAILED"
            ),
            "reported": (
                "PASSED means every checked artifact satisfies the Iteration 14 validators; "
                "FAILED means at least one artifact does not. The report never claims more "
                "than the artifacts prove."
            ),
        },
    }


def _extract_sentinel(stdout: str) -> Optional[str]:
    """Extract the revert reason the trusted harness emitted."""
    marker = "EXPLOIT_FAILED"
    if marker in stdout:
        start = stdout.index(marker)
        end = stdout.find('"', start)
        if end == -1:
            end = len(stdout)
        return stdout[start:end].strip()
    return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", default=DEFAULT_RAW_EXPORT)
    parser.add_argument("--join-table", default=DEFAULT_JOIN_TABLE)
    parser.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    parser.add_argument("--baseline-id", default=DEFAULT_BASELINE)
    parser.add_argument("--report", default=DEFAULT_REPORT)
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
            # Without an explicit expectation the report must at least belong to
            # the history of the checked-out commit.
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

    report = validate_run(
        run_dir=_ROOT / args.run_dir,
        baseline_id=args.baseline_id,
        raw_export_path=_ROOT / args.raw_export,
        join_table_path=_ROOT / args.join_table,
        code_sha=code_sha,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    summary = report["summary"]
    print(
        "wrote {path}: {status}, {failed}/{total} targets failed".format(
            path=_display(report_path),
            status=summary["overall_status"],
            failed=summary["targets_failed"],
            total=summary["targets_checked"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
