"""
tests/test_iteration15_evidence_integrity.py
===========================================

Iteration 15 (PR #12 follow-up) - residual P0 acceptance fixes.

The Iteration 14 review named two remaining validator weaknesses:

1. A billing attribution was accepted when a target carried a non-empty
   ``invocation_id`` plus an App ID, and an App/resource/interval aggregate
   bucket could be allocated to an individual target.
2. A ``NOT_AVAILABLE`` provenance fact was accepted with a reason string
   alone: a missing, malformed or tampered evidence reference was not
   detected, and App IDs were never cross-checked against the billing export.

Every requirement gets a positive test (the honest case must pass) and a set
of negative tests (every way of cheating must fail).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    APP_ID_MATCHED,
    APP_ID_MISMATCHED,
    APP_ID_NOT_COMPARED,
    JOIN_REASON_AMBIGUOUS,
    JOIN_REASON_APP_MISMATCH,
    JOIN_REASON_BUCKET,
    JOIN_REASON_MISSING_KEY,
    JOIN_REASON_MISSING_VALUE,
    JOIN_REASON_NO_MATCH,
    JOIN_REASON_NO_JOIN,
    JOIN_REASON_UNSUPPORTED_FIELD,
    NOT_AVAILABLE,
    OBSERVED,
    PROVIDER_JOIN_FIELDS,
    attach_evidence_ref_to_facts,
    build_billing_attribution,
    build_evidence_ref_from_bytes,
    cross_check_app_ids,
    load_raw_billing_line_items,
    not_available,
    observed,
    resolve_billing_join,
    resolve_evidence_path,
    sha256_bytes,
    validate_billing_attribution,
    validate_evidence_ref_bytes,
    validate_modal_app_id_consistency,
    validate_modal_invocation_provenance,
)

RAW_EXPORT = _ROOT / "benchmarks" / "evidence" / "modal_billing_report_raw.json"
JOIN_TABLE = _ROOT / "benchmarks" / "evidence" / "modal_billing_join_table.json"
RUN_DIR = _ROOT / "benchmarks" / "artifacts" / "run_1794209615_70f5d22"
BASELINE_DIR = RUN_DIR / "baseline_5"
VALIDATION_EVIDENCE = _ROOT / "benchmarks" / "evidence" / "iteration15_validation_evidence.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _billing_items_with_provider_keys(tmp_path: Path):
    """A raw export that carries a provider correlation identifier."""
    raw = [
        {
            "object_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            "description": "aegis-rlvr-security",
            "environment": "main",
            "interval_start": "2026-11-09T00:00:00",
            "resource": "H100",
            "cost": "0.74323683",
            "invocation_id": "fc-UNIQUEONE",
        },
        {
            "object_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            "description": "aegis-rlvr-security",
            "environment": "main",
            "interval_start": "2026-11-09T00:00:00",
            "resource": "CPU",
            "cost": "0.03001687",
            "invocation_id": "fc-UNIQUETWO",
        },
    ]
    path = tmp_path / "raw_with_provider_keys.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return load_raw_billing_line_items(path)


def _target_row(target_id: str = "REENT-01"):
    return [{"target_id": target_id, "target_name": "Vault", "app_id": "ap-EDUitOwWeMrIdYbTh4kB63"}]


def _observed_stage(**overrides):
    from benchmarks.evidence_integrity import build_modal_stage_provenance

    stage = build_modal_stage_provenance(
        function_name="verify_exploit_remote",
        app_id=observed("ap-EDUitOwWeMrIdYbTh4kB63", source="modal.running_app().app_id"),
        function_call_id=observed("fc-8Hq2ZpQrVt3Lb", source="modal.current_function_call_id()"),
        container_id=observed("hokkglpxczflmxlcnxxg", source="MODAL_WORKER_ID of the container"),
        resource="CPU",
        attempted=True,
    )
    stage.update(overrides)
    return stage


def _evidence_artifact(tmp_path: Path, payload: Optional[bytes] = None):
    """
    Write a byte-exact stage evidence artifact and describe it.

    Since Iteration 16 the evidence of a stage must declare the stage it
    belongs to and must carry the typed absence record of the field the fact
    claims to be missing. The file name and the digest semantics are the ones
    of Iteration 15, so every adversarial check of this suite keeps its intent.
    """
    from benchmarks.evidence_integrity import (
        StageResponseCapture,
        build_stage_evidence_artifact,
    )

    if payload is None:
        artifact = build_stage_evidence_artifact(
            StageResponseCapture(
                stage="evm_sandbox",
                attempted=True,
                executed=True,
                response_received=True,
                provider_response={"modal_runtime": {}},
                runtime_identity={},
                runtime_identity_source="modal_runtime",
                response_source="the response of verify_exploit_remote",
            ),
            target_id="REENT-01",
            correlation_id="corr-test",
        )
        payload = json.dumps(
            artifact, indent=2, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")

    path = tmp_path / "runtime_evidence.json"
    path.write_bytes(payload)
    return build_evidence_ref_from_bytes(
        "runtime_evidence.json", payload, description="the runtime payload the worker returned"
    )


def _provenance_with_stage(stage: dict):
    return {
        "target_id": "REENT-01",
        "modal_invocation_provenance": {
            "modal_app_id": observed(
                "ap-EDUitOwWeMrIdYbTh4kB63", source="modal.running_app().app_id"
            ),
            "stages": {"evm_sandbox": stage},
        },
    }


# ===========================================================================
# 1) Billing attribution must prove an exact, unique join
# ===========================================================================

def test_iteration15_billing_accepts_unique_provider_backed_join(tmp_path):
    """The honest case: a provider id that occurs on exactly one raw record."""
    items = _billing_items_with_provider_keys(tmp_path)
    attribution = build_billing_attribution(
        items,
        target_rows=_target_row(),
        invocation_joins={
            "REENT-01": {
                "provider_field": "invocation_id",
                "provider_value": "fc-UNIQUEONE",
                "app_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            }
        },
    )

    row = attribution.target_level[0]
    assert row["cost_usd"] == pytest.approx(0.74323683)
    assert row["cost_status"] == "ATTRIBUTED"
    assert row["cost_reason_code"] is None
    assert row["invocation_join"]["provider_field"] == "invocation_id"
    assert row["invocation_join"]["provider_value"] == "fc-UNIQUEONE"

    ok, err = validate_billing_attribution(attribution.to_dict(), items)
    assert ok is True, err


def test_iteration15_billing_rejects_fabricated_invocation_id(tmp_path):
    """An identifier that occurs on no raw record is not evidence."""
    items = _billing_items_with_provider_keys(tmp_path)
    attribution = build_billing_attribution(
        items,
        target_rows=_target_row(),
        invocation_joins={
            "REENT-01": {
                "provider_field": "invocation_id",
                "provider_value": "fc-FABRICATED",
                "app_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            }
        },
    )

    # The fabricated identifier is not honoured: the target stays unattributed
    # and says why.
    row = attribution.target_level[0]
    assert row["cost_usd"] is None
    assert row["cost_reason_code"] == JOIN_REASON_NO_MATCH
    assert row["cost_reason"]
    assert row["invocation_join"] is None

    # Publishing a cost for that fabricated identifier is rejected.
    forged = attribution.to_dict()
    forged["target_level"][0]["cost_usd"] = 0.74323683
    forged["target_level"][0]["cost_usd_exact"] = "0.74323683"
    forged["target_level"][0]["invocation_join"] = {
        "provider_field": "invocation_id",
        "provider_value": "fc-FABRICATED",
        "app_id": "ap-EDUitOwWeMrIdYbTh4kB63",
        "line_item_key": items[0].key,
    }

    ok, err = validate_billing_attribution(forged, items)
    assert ok is False
    assert "without a proven invocation-level join" in err
    assert JOIN_REASON_NO_MATCH in err


def test_iteration15_billing_rejects_wrong_app_id(tmp_path):
    """A join that names another application is rejected."""
    items = _billing_items_with_provider_keys(tmp_path)
    attribution = build_billing_attribution(
        items,
        target_rows=_target_row(),
        invocation_joins={
            "REENT-01": {
                "provider_field": "invocation_id",
                "provider_value": "fc-UNIQUEONE",
                "app_id": "ap-SomeOtherApplication",
            }
        },
    )

    row = attribution.target_level[0]
    assert row["cost_usd"] is None
    assert row["cost_reason_code"] == JOIN_REASON_APP_MISMATCH


def test_iteration15_billing_rejects_duplicate_billing_row(tmp_path):
    """A duplicated billing record makes the correlation ambiguous."""
    raw = [
        {
            "object_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            "description": "aegis-rlvr-security",
            "environment": "main",
            "interval_start": "2026-11-09T00:00:00",
            "resource": "H100",
            "cost": "0.74323683",
            "invocation_id": "fc-DUPLICATED",
        },
        {
            "object_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            "description": "aegis-rlvr-security",
            "environment": "main",
            "interval_start": "2026-11-09T00:00:00",
            "resource": "H100",
            "cost": "0.74323683",
            "invocation_id": "fc-DUPLICATED",
        },
    ]
    path = tmp_path / "raw_duplicated.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    items = load_raw_billing_line_items(path)

    matched, reason = resolve_billing_join(
        {"provider_field": "invocation_id", "provider_value": "fc-DUPLICATED"}, items
    )
    assert matched is None
    assert reason == JOIN_REASON_AMBIGUOUS

    attribution = build_billing_attribution(
        items,
        target_rows=_target_row(),
        invocation_joins={
            "REENT-01": {"provider_field": "invocation_id", "provider_value": "fc-DUPLICATED"}
        },
    )
    assert attribution.target_level[0]["cost_usd"] is None
    assert attribution.target_level[0]["cost_reason_code"] == JOIN_REASON_AMBIGUOUS


def test_iteration15_billing_rejects_ambiguous_provider_join(tmp_path):
    """One invocation matching multiple rows is not a unique correlation."""
    items = _billing_items_with_provider_keys(tmp_path)
    raw_item = items[0]
    # A second raw record carrying the same provider identifier.
    from benchmarks.evidence_integrity import BillingLineItem

    duplicate = BillingLineItem(
        object_id=raw_item.object_id,
        resource="CPU",
        cost_usd=0.01,
        interval_start=raw_item.interval_start,
        description=raw_item.description,
        environment=raw_item.environment,
        index=99,
        provider_join_keys=dict(raw_item.provider_join_keys),
    )

    matched, reason = resolve_billing_join(
        {"provider_field": "invocation_id", "provider_value": "fc-UNIQUEONE"},
        list(items) + [duplicate],
    )
    assert matched is None
    assert reason == JOIN_REASON_AMBIGUOUS


def test_iteration15_billing_rejects_two_targets_sharing_one_bucket(tmp_path):
    """Two targets may never receive the same billing record."""
    items = _billing_items_with_provider_keys(tmp_path)
    attribution = build_billing_attribution(
        items,
        target_rows=_target_row("REENT-01") + _target_row("REENT-02"),
        invocation_joins={
            "REENT-01": {
                "provider_field": "invocation_id",
                "provider_value": "fc-UNIQUEONE",
                "app_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            },
            "REENT-02": {
                "provider_field": "invocation_id",
                "provider_value": "fc-UNIQUEONE",
                "app_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            },
        },
    )

    first, second = attribution.target_level
    assert first["cost_usd"] is not None
    assert second["cost_usd"] is None
    assert second["cost_reason_code"] == "ALREADY_CLAIMED_BY_ANOTHER_TARGET"


def test_iteration15_billing_rejects_missing_join_key(tmp_path):
    """A join without a documented provider field identifies no record."""
    items = _billing_items_with_provider_keys(tmp_path)

    matched, reason = resolve_billing_join({}, items)
    assert matched is None
    assert reason == JOIN_REASON_MISSING_KEY

    matched, reason = resolve_billing_join(
        {"provider_field": "invocation_id", "provider_value": ""}, items
    )
    assert matched is None
    assert reason == JOIN_REASON_MISSING_VALUE

    matched, reason = resolve_billing_join(
        {"provider_field": "correlation_id", "provider_value": "corr-1"}, items
    )
    assert matched is None
    assert reason == JOIN_REASON_UNSUPPORTED_FIELD


def test_iteration15_billing_rejects_aggregate_bucket_allocation(tmp_path):
    """An App/resource/interval bucket is never allocated to a target."""
    items = _billing_items_with_provider_keys(tmp_path)

    matched, reason = resolve_billing_join(
        {
            "app_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            "resource": "H100",
            "interval_start": "2026-11-09T00:00:00",
        },
        items,
    )
    assert matched is None
    assert reason == JOIN_REASON_BUCKET

    attribution = build_billing_attribution(
        items,
        target_rows=_target_row(),
        invocation_joins={
            "REENT-01": {
                "app_id": "ap-EDUitOwWeMrIdYbTh4kB63",
                "resource": "H100",
                "interval_start": "2026-11-09T00:00:00",
            }
        },
    )
    row = attribution.target_level[0]
    assert row["cost_usd"] is None
    assert row["cost_reason_code"] == JOIN_REASON_BUCKET


def test_iteration15_billing_rejects_cost_that_does_not_match_the_joined_record(tmp_path):
    """The published cost must equal the joined record's cost exactly."""
    items = _billing_items_with_provider_keys(tmp_path)
    attribution = build_billing_attribution(
        items,
        target_rows=_target_row(),
        invocation_joins={
            "REENT-01": {
                "provider_field": "invocation_id",
                "provider_value": "fc-UNIQUEONE",
                "app_id": "ap-EDUitOwWeMrIdYbTh4kB63",
            }
        },
    ).to_dict()

    attribution["target_level"][0]["cost_usd"] = 0.5
    attribution["target_level"][0]["cost_usd_exact"] = "0.5"

    ok, err = validate_billing_attribution(attribution, items)
    assert ok is False
    assert "does not equal the cost of the joined billing record" in err


def test_iteration15_billing_requires_reason_code_for_unattributed_target(tmp_path):
    """An unattributed target must say why, in machine-readable form."""
    items = _billing_items_with_provider_keys(tmp_path)
    attribution = build_billing_attribution(items, target_rows=_target_row()).to_dict()

    assert attribution["target_level"][0]["cost_usd"] is None
    assert attribution["target_level"][0]["cost_reason_code"] == JOIN_REASON_NO_JOIN

    attribution["target_level"][0]["cost_reason_code"] = None
    ok, err = validate_billing_attribution(attribution, items)
    assert ok is False
    assert "machine-readable" in err


def test_iteration15_billing_rejects_cost_without_any_join(tmp_path):
    """A cost without a join is rejected, exactly as before."""
    items = _billing_items_with_provider_keys(tmp_path)
    attribution = build_billing_attribution(items, target_rows=_target_row()).to_dict()
    attribution["target_level"][0]["cost_usd"] = 0.74323683

    ok, err = validate_billing_attribution(attribution, items)
    assert ok is False
    assert "without a proven invocation-level join" in err


def test_iteration15_saved_join_table_is_schema_3_and_validates():
    """The published join table is schema 3.0.0 and reconciles exactly."""
    items = load_raw_billing_line_items(RAW_EXPORT)
    join_table = json.loads(JOIN_TABLE.read_text(encoding="utf-8"))

    assert join_table["schema_version"] == "3.0.0"
    ok, err = validate_billing_attribution(
        join_table, items, known_app_ids=[item.object_id for item in items]
    )
    assert ok is True, err

    # The raw export carries no provider correlation identifier, so no target
    # may carry a cost, and every one of them must state why.
    for row in join_table["target_level"]:
        assert row["cost_usd"] is None
        assert row["cost_reason_code"]
        assert row["cost_reason"]

    # The aggregate bucket is never allocated to a target.
    assert join_table["attribution_policy"]["aggregate_bucket_allocation"] == "FORBIDDEN"
    assert "provider_join_fields" in join_table["attribution_policy"]


def test_iteration15_provider_join_fields_are_documented():
    """The documented provider correlation fields are exactly the allowed ones."""
    assert PROVIDER_JOIN_FIELDS == ("invocation_id", "function_call_id", "task_id")


# ===========================================================================
# 2) Modal provenance evidence must be independently verifiable
# ===========================================================================

def test_iteration15_provenance_rejects_not_available_without_evidence_ref(tmp_path):
    """A reason string alone is not sufficient."""
    stage = _observed_stage(
        app_id=not_available("the runtime did not expose an application id")
    )
    ok, err = validate_modal_invocation_provenance(
        _provenance_with_stage(stage), evidence_root=tmp_path
    )
    assert ok is False
    assert "without an explicit reason" not in err
    assert "has no evidence reference" in err


def test_iteration15_provenance_rejects_not_available_without_digest(tmp_path):
    """An evidence reference without a digest proves nothing."""
    stage = _observed_stage(
        app_id=not_available(
            "the runtime did not expose an application id",
            evidence_ref={"path": "runtime_evidence.json"},
        )
    )
    ok, err = validate_modal_invocation_provenance(
        _provenance_with_stage(stage), evidence_root=tmp_path
    )
    assert ok is False
    assert "no valid SHA-256 digest" in err


def test_iteration15_provenance_rejects_malformed_digest(tmp_path):
    """A malformed digest is rejected."""
    ref = _evidence_artifact(tmp_path)
    broken = dict(ref)
    broken["sha256"] = "not-a-sha256"
    stage = _observed_stage(
        app_id=not_available("the runtime did not expose an application id", evidence_ref=broken)
    )
    ok, err = validate_modal_invocation_provenance(
        _provenance_with_stage(stage), evidence_root=tmp_path
    )
    assert ok is False
    assert "no valid SHA-256 digest" in err


def test_iteration15_provenance_rejects_tampered_evidence_bytes(tmp_path):
    """The digest is validated against the bytes that are actually stored."""
    ref = _evidence_artifact(tmp_path)
    stage = _observed_stage(
        app_id=not_available("the runtime did not expose an application id", evidence_ref=ref)
    )
    artifact = _provenance_with_stage(stage)

    # The honest state passes.
    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is True, err

    # Tampering with the stored bytes is detected.
    (tmp_path / "runtime_evidence.json").write_bytes(b'{"reported": {"app_id": "ap-fake"}}\n')
    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "does not match the digest of the referenced bytes" in err


def test_iteration15_provenance_rejects_missing_evidence_artifact(tmp_path):
    """A reference to an artifact that does not exist is rejected."""
    ref = _evidence_artifact(tmp_path)
    stage = _observed_stage(
        app_id=not_available("the runtime did not expose an application id", evidence_ref=ref)
    )
    (tmp_path / "runtime_evidence.json").unlink()

    ok, err = validate_modal_invocation_provenance(
        _provenance_with_stage(stage), evidence_root=tmp_path
    )
    assert ok is False
    assert "missing artifact" in err


def test_iteration15_provenance_rejects_evidence_path_outside_the_evidence_root(tmp_path):
    """An evidence reference may never point outside the evidence root."""
    absolute = _evidence_artifact(tmp_path)
    outside = dict(absolute)
    outside["path"] = str((tmp_path / "runtime_evidence.json").resolve())
    stage = _observed_stage(
        app_id=not_available("the runtime did not expose an application id", evidence_ref=outside)
    )

    ok, err = validate_modal_invocation_provenance(
        _provenance_with_stage(stage), evidence_root=tmp_path
    )
    assert ok is False
    assert "not a relative path inside the evidence root" in err


def test_iteration15_provenance_accepts_not_available_with_verified_evidence(tmp_path):
    """The honest unavailable case: a reason plus a verifiable reference."""
    ref = _evidence_artifact(tmp_path)
    stage = _observed_stage(
        app_id=not_available(
            "the runtime did not expose an application id", evidence_ref=ref
        )
    )
    ok, err = validate_modal_invocation_provenance(
        _provenance_with_stage(stage), evidence_root=tmp_path
    )
    assert ok is True, err


def test_iteration15_provenance_accepts_fully_observed_facts(tmp_path):
    """The fully observed case keeps working."""
    artifact = _provenance_with_stage(_observed_stage())
    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is True, err


def test_iteration15_provenance_rejects_app_id_mismatch(tmp_path):
    """An observed App ID that the billing export does not contain is rejected."""
    artifact = _provenance_with_stage(_observed_stage())
    ok, err = validate_modal_invocation_provenance(
        artifact,
        known_app_ids=["ap-SomeOtherApplication"],
        evidence_root=tmp_path,
    )
    assert ok is False
    assert "absent from the raw billing export" in err


def test_iteration15_provenance_accepts_matching_app_id(tmp_path):
    """An observed App ID that the billing export contains is accepted."""
    artifact = _provenance_with_stage(_observed_stage())
    ok, err = validate_modal_invocation_provenance(
        artifact,
        known_app_ids=["ap-EDUitOwWeMrIdYbTh4kB63"],
        evidence_root=tmp_path,
    )
    assert ok is True, err


def test_iteration15_provenance_records_unavailable_app_id_explicitly(tmp_path):
    """An unavailable App ID is reported, never silently skipped."""
    ref = _evidence_artifact(tmp_path)
    stage = _observed_stage(
        app_id=not_available(
            "the runtime did not expose an application id", evidence_ref=ref
        )
    )
    artifact = _provenance_with_stage(stage)

    report = cross_check_app_ids(artifact, ["ap-EDUitOwWeMrIdYbTh4kB63"])
    scopes = {record["scope"]: record for record in report["comparisons"]}
    assert scopes["stages.evm_sandbox.app_id"]["status"] == APP_ID_NOT_COMPARED
    assert scopes["stages.evm_sandbox.app_id"]["reason"]
    assert scopes["modal_app_id"]["status"] == APP_ID_MATCHED

    ok, err = validate_modal_app_id_consistency(artifact, ["ap-EDUitOwWeMrIdYbTh4kB63"])
    assert ok is True, err


def test_iteration15_provenance_cross_check_reports_mismatch():
    """The cross-check itself reports the mismatch."""
    artifact = _provenance_with_stage(_observed_stage())
    report = cross_check_app_ids(artifact, ["ap-SomeOtherApplication"])
    assert report["status"] == "FAILED"
    assert any(r["status"] == APP_ID_MISMATCHED for r in report["comparisons"])


def test_iteration15_evidence_ref_bytes_helper_validates_the_digest(tmp_path):
    """The low-level helper verifies the digest against the stored bytes."""
    ref = _evidence_artifact(tmp_path)
    ok, err = validate_evidence_ref_bytes(ref, evidence_root=tmp_path)
    assert ok is True, err
    assert ref["sha256"] == sha256_bytes((tmp_path / "runtime_evidence.json").read_bytes())


def test_iteration15_resolve_evidence_path_rejects_traversal(tmp_path):
    """A path that escapes the evidence root is rejected."""
    assert resolve_evidence_path("../outside.json", evidence_root=tmp_path) is None
    assert resolve_evidence_path("inside.json", evidence_root=tmp_path) is not None


def test_iteration15_attach_evidence_ref_to_facts_is_recursive(tmp_path):
    """Every NOT_AVAILABLE fact of a payload receives the reference."""
    ref = _evidence_artifact(tmp_path)
    payload = {
        "stages": {
            "inference": {
                "app_id": not_available("the runtime did not report the application id"),
                "container_id": observed("hokkglpxczflmxlcnxxg", source="MODAL_WORKER_ID"),
            }
        }
    }
    updated = attach_evidence_ref_to_facts(payload, ref)

    fact = updated["stages"]["inference"]["app_id"]
    assert fact["evidence_ref"]["sha256"] == ref["sha256"]
    # The original payload is never mutated.
    assert "evidence_ref" not in payload["stages"]["inference"]["app_id"]


# ===========================================================================
# 3) Validation artifact
# ===========================================================================

def test_iteration15_validation_evidence_is_bound_to_the_code_sha():
    """The published validation evidence must name the code SHA it came from."""
    assert VALIDATION_EVIDENCE.is_file(), "the Iteration 15 validation evidence is missing"
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))

    assert report["generator"] == "benchmarks/validate_iteration15_evidence.py"

    code_sha = report["code_sha"]
    assert isinstance(code_sha, str) and re.fullmatch(r"[0-9a-f]{40}", code_sha), code_sha

    result = subprocess.run(
        ["git", "cat-file", "-t", code_sha],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"{code_sha} is not a commit of this repository"

    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", code_sha, "HEAD"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert ancestor.returncode == 0, (
        f"{code_sha} is not an ancestor of HEAD; the evidence must belong to this branch"
    )


def test_iteration15_validation_evidence_separates_observed_from_unavailable():
    """Observed facts and unavailable facts stay distinguishable."""
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    assert report["per_target"], "the report must carry the per-target results"

    for entry in report["per_target"]:
        facts = entry["provider_facts"]
        assert facts["observed"] or facts["not_available"]
        for fact in facts["observed"]:
            assert fact["status"] == "OBSERVED"
            assert fact["value"] is not None
        for fact in facts["not_available"]:
            assert fact["status"] == NOT_AVAILABLE
            assert fact["reason"]


def test_iteration15_validation_evidence_reports_the_saved_run_honestly():
    """
    The saved run predates this fix, so the report must say so.

    A report that claimed PASSED for artifacts that violate the new validators
    would be exactly the kind of false success state this task forbids.
    """
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))

    summary = report["summary"]
    assert summary["targets_checked"] == 16
    assert summary["overall_status"] == "FAILED"

    for key in ("planned", "attempted", "executed", "observed", "reported"):
        assert report["interpretation"][key]

    # No Modal runtime validation may be claimed.
    assert "no modal runtime validation is claimed" in report["interpretation"]["reported"].lower()


def test_iteration15_validation_evidence_check_mode_detects_a_foreign_code_sha(tmp_path):
    """The --check mode must refuse a report that belongs to another commit."""
    from benchmarks.validate_iteration15_evidence import main

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    report["code_sha"] = "0" * 40
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps(report), encoding="utf-8")

    exit_code = main(["--check", "--report", str(foreign), "--code-sha", "a" * 40])
    assert exit_code == 1


def test_iteration15_ci_workflow_runs_the_new_suite():
    """CI must execute the Iteration 15 suite."""
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "tests/test_iteration15_evidence_integrity.py" in ci
    assert "benchmarks.validate_iteration15_evidence" in ci
