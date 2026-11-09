"""
benchmarks/regenerate_billing_join_table.py
=============================================

Regenerate the Modal billing join table from the immutable raw provider export
(Iteration 14 P0.1, hardened in Iteration 15).

The previous table (schema 1.0.0) bound every one of the 16 targets to a single
Modal application id and repeated the *aggregated* application-level charge on
every target row, so the same raw line item was accounted for many times. It
also published fabricated ``modal-app://`` provider log URIs.

This generator produces schema 3.0.0:

* ``app_session_level`` accounts for **every** raw billing line item exactly
  once, grouped by (app id, resource, interval);
* ``target_level`` keeps ``cost_usd = null`` unless an *exact* provider-backed
  join to a single raw line item was proven: the join must name a documented
  provider correlation field whose value occurs on exactly one raw record, and
  that record must belong to the application the target claims;
* every unattributed target carries a machine-readable ``cost_reason_code``;
* every referenced application id is checked against the raw export;
* the aggregates are reconciled with :class:`decimal.Decimal` arithmetic.

The raw export carries no provider-level correlation identifier, so every
target stays unattributed with the reason ``NO_JOIN_PROVIDED``. That is the
honest state of the data, not a defect of the generator.

Usage::

    python -m benchmarks.regenerate_billing_join_table
    python -m benchmarks.regenerate_billing_join_table --check
"""

from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    build_billing_attribution,
    file_sha256,
    load_raw_billing_line_items,
    validate_billing_attribution,
)

DEFAULT_RAW_EXPORT = "benchmarks/evidence/modal_billing_report_raw.json"
DEFAULT_JOIN_TABLE = "benchmarks/evidence/modal_billing_join_table.json"
DEFAULT_VALIDATION = "benchmarks/evidence/modal_control_harness_validation.json"
DEFAULT_DATASET = "benchmarks/benchmark_dataset.json"
DEFAULT_RUN_DIR = "benchmarks/artifacts/run_1794209615_70f5d22"
DEFAULT_BASELINE = "baseline_5"


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _dataset_targets(dataset_path: Path) -> List[Dict[str, Any]]:
    """Flatten the benchmark dataset into the public target list."""
    dataset = _read_json(dataset_path)
    targets: List[Dict[str, Any]] = []
    for klass in dataset.get("classes", []):
        for target in klass.get("targets", []):
            targets.append(target)
    for control in dataset.get("synthetic_controls", []):
        targets.append(control)
    return targets


def _run_artifact_rows(run_dir: Path, baseline_id: str) -> Dict[str, Dict[str, Any]]:
    """Load the per-target artifacts of one baseline of one run."""
    rows: Dict[str, Dict[str, Any]] = {}
    baseline_dir = run_dir / baseline_id
    if not baseline_dir.is_dir():
        return rows
    for artifact_path in sorted(baseline_dir.glob("*.json")):
        try:
            artifact = _read_json(artifact_path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(artifact, dict) or "target_id" not in artifact:
            continue
        rows[str(artifact["target_id"])] = artifact
    return rows


def _canonical_run_app_session(validation_path: Path) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Read the canonical run application session from the immutable validation
    artifact and return it together with a content-addressed evidence reference.
    """
    if not validation_path.is_file():
        return None, {}
    validation = _read_json(validation_path)
    app_id = None
    if isinstance(validation, dict):
        audit = validation.get("modal_billing_audit")
        if isinstance(audit, dict):
            app_id = audit.get("canonical_run_app_session")
        if not app_id:
            app_id = validation.get("canonical_run_app_session")
    if not app_id:
        return None, {}
    evidence_ref = {
        "path": str(validation_path.relative_to(_ROOT)).replace("\\", "/"),
        "sha256": file_sha256(validation_path),
        "field": "canonical_run_app_session",
    }
    return str(app_id), evidence_ref


def _provider_joins(
    artifacts: Dict[str, Dict[str, Any]],
    targets: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Collect the provider-backed joins the saved artifacts really support.

    A join is only attempted when the target artifact records an observed
    provider correlation identifier (a function-call id or another documented
    provider key) that the raw export can be searched for. Nothing is
    invented here: a target without such an identifier simply gets no join.
    """
    from benchmarks.evidence_integrity import PROVIDER_JOIN_FIELDS

    joins: Dict[str, Dict[str, Any]] = {}
    for target in targets:
        target_id = str(target.get("contract_id", ""))
        artifact = artifacts.get(target_id) or {}
        provenance = artifact.get("modal_invocation_provenance") or {}
        stages = provenance.get("stages") or {}
        if not isinstance(stages, dict):
            continue

        for stage in stages.values():
            if not isinstance(stage, dict):
                continue
            for provider_field in PROVIDER_JOIN_FIELDS:
                fact = stage.get(provider_field)
                if not isinstance(fact, dict) or fact.get("status") != "OBSERVED":
                    continue
                value = fact.get("value")
                if not value:
                    continue
                joins[target_id] = {
                    "provider_field": provider_field,
                    "provider_value": str(value),
                    "app_id": stage.get("app_id", {}).get("value")
                    if isinstance(stage.get("app_id"), dict)
                    else None,
                }
                break
            if target_id in joins:
                break

    return joins


def generate_join_table(
    *,
    raw_export_path: Path,
    dataset_path: Path,
    validation_path: Path,
    run_dir: Path,
    baseline_id: str,
) -> Dict[str, Any]:
    """Build the schema 3.0.0 billing join table."""
    line_items = load_raw_billing_line_items(raw_export_path)
    targets = _dataset_targets(dataset_path)
    artifacts = _run_artifact_rows(run_dir, baseline_id)
    run_app_id, run_app_evidence = _canonical_run_app_session(validation_path)

    target_rows: List[Dict[str, Any]] = []
    for target in targets:
        target_id = str(target.get("contract_id", ""))
        artifact = artifacts.get(target_id, {})
        tool_meta = artifact.get("tool_metadata", {}) if isinstance(artifact, dict) else {}
        target_rows.append(
            {
                "target_id": target_id,
                "target_name": target.get("target_name"),
                "app_id": run_app_id,
                "correlation_id": tool_meta.get("correlation_id"),
                "orchestration_status": artifact.get("orchestration_status"),
                "generation_outcome": artifact.get("generation_outcome"),
                "evm_outcome": artifact.get("evm_outcome"),
                "security_verdict": artifact.get("security_verdict"),
                "replay_status": artifact.get("replay_status"),
                "artifact_present": bool(artifact),
            }
        )

    # Only a provider-backed, exact join may give a target a cost. The raw
    # export of this run carries no provider correlation identifier, so no
    # target receives one.
    invocation_joins = _provider_joins(artifacts, targets)
    attribution = build_billing_attribution(
        line_items,
        target_rows=target_rows,
        invocation_joins=invocation_joins,
    )

    for row in attribution.app_session_level:
        row["belongs_to_canonical_run_app_session"] = (
            run_app_id is not None and row.get("app_id") == run_app_id
        )

    raw_total = sum(Decimal(str(item.cost_usd)) for item in line_items)
    canonical_total = sum(
        Decimal(str(row["cost_usd"]))
        for row in attribution.app_session_level
        if row.get("belongs_to_canonical_run_app_session")
    )
    h100_total = sum(
        Decimal(str(item.cost_usd)) for item in line_items if item.resource == "H100"
    )

    known_app_ids = sorted({item.object_id for item in line_items})
    for row in attribution.target_level:
        row["app_id_evidence_ref"] = run_app_evidence if row.get("app_id") else None

    join_table: Dict[str, Any] = {
        "schema_version": "3.0.0",
        "generated_by": "benchmarks/regenerate_billing_join_table.py",
        "description": (
            "Modal billing attribution split into application/session level (every raw line "
            "item accounted for exactly once) and target level (a cost is only published for an "
            "exact, unique provider-backed join to a single raw billing record)."
        ),
        "source_raw_export": {
            "path": str(raw_export_path.relative_to(_ROOT)).replace("\\", "/"),
            "sha256": file_sha256(raw_export_path),
            "line_item_count": len(line_items),
            "total_cost_usd": float(raw_total),
        },
        "run": {
            "run_id": run_dir.name,
            "baseline_id": baseline_id,
            "run_dir": str(run_dir.relative_to(_ROOT)).replace("\\", "/"),
            "targets_count": len(target_rows),
            "artifacts_found": sum(1 for row in target_rows if row["artifact_present"]),
        },
        "canonical_run_app_session": {
            "app_id": run_app_id,
            "status": "OBSERVED" if run_app_id else "NOT_AVAILABLE",
            "reason": None
            if run_app_id
            else (
                "the immutable validation artifact does not record a canonical run "
                "application session"
            ),
            "evidence_ref": run_app_evidence or None,
        },
        "app_session_level": attribution.app_session_level,
        "target_level": attribution.target_level,
        "totals": {
            "raw_export_total_cost_usd": float(raw_total),
            "canonical_run_app_session_total_cost_usd": float(canonical_total),
            "h100_total_cost_usd": float(h100_total),
            "h100_line_item_count": sum(1 for item in line_items if item.resource == "H100"),
            "app_session_row_count": len(attribution.app_session_level),
            "target_row_count": len(attribution.target_level),
        },
        "attribution_policy": attribution.attribution_policy,
    }

    ok, error = validate_billing_attribution(
        join_table, line_items, known_app_ids=known_app_ids
    )
    join_table["validation"] = {
        "status": "PASSED" if ok else "FAILED",
        "error": error,
        "checks": [
            "every raw line item is accounted for exactly once",
            "no raw line item is counted twice",
            "every referenced application id exists in the raw export",
            "aggregates reconcile exactly with the raw export",
            "no target carries a cost without an exact provider-backed join",
            "no two targets claim the same billing record",
            "every unattributed target carries a machine-readable cost_reason_code",
        ],
    }
    if not ok:
        raise ValueError(f"generated billing join table does not validate: {error}")
    return join_table


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", default=DEFAULT_RAW_EXPORT)
    parser.add_argument("--join-table", default=DEFAULT_JOIN_TABLE)
    parser.add_argument("--validation", default=DEFAULT_VALIDATION)
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    parser.add_argument("--baseline-id", default=DEFAULT_BASELINE)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the existing join table without rewriting it",
    )
    args = parser.parse_args(argv)

    raw_export_path = _ROOT / args.raw_export
    join_table_path = _ROOT / args.join_table
    validation_path = _ROOT / args.validation
    dataset_path = _ROOT / args.dataset
    run_dir = _ROOT / args.run_dir

    if args.check:
        line_items = load_raw_billing_line_items(raw_export_path)
        existing = _read_json(join_table_path)
        known_app_ids = sorted({item.object_id for item in line_items})
        ok, error = validate_billing_attribution(
            existing, line_items, known_app_ids=known_app_ids
        )
        print(f"join table validation: {'PASSED' if ok else 'FAILED'} ({error or 'no error'})")
        return 0 if ok else 1

    join_table = generate_join_table(
        raw_export_path=raw_export_path,
        dataset_path=dataset_path,
        validation_path=validation_path,
        run_dir=run_dir,
        baseline_id=args.baseline_id,
    )
    with open(join_table_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(join_table, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    totals = join_table["totals"]
    print(
        "wrote {path}: {rows} app/session rows, {targets} target rows, "
        "raw total ${raw}, canonical run session ${canonical}".format(
            path=join_table_path.relative_to(_ROOT),
            rows=totals["app_session_row_count"],
            targets=totals["target_row_count"],
            raw=totals["raw_export_total_cost_usd"],
            canonical=totals["canonical_run_app_session_total_cost_usd"],
        )
    )
    print(f"validation: {join_table['validation']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
