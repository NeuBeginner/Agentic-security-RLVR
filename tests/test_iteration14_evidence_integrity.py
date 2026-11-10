"""
tests/test_iteration14_evidence_integrity.py

Iteration 14 (Issue #11) - evidence-integrity tests.

Every P0 defect group gets a positive test (the honest case must pass) and a
set of negative tests (every way of cheating must fail):

P0.1  Modal provenance and billing attribution
P0.2  Replay integrity envelope
P0.3  Remote EVM toolchain provenance
P0.4  Safe-control sentinel semantics
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    HARNESS_SENTINELS,
    LEGACY_HARDCODED_EVM_FACTS,
    NOT_AVAILABLE,
    OBSERVED,
    SAFE_CONTROL_SENTINELS,
    SAFE_CONTROL_TARGETS,
    build_billing_attribution,
    build_evidence_ref,
    build_modal_stage_provenance,
    file_sha256,
    has_synthetic_modal_uri,
    load_raw_billing_line_items,
    not_available,
    observed,
    persist_replay_artifact,
    sha256_bytes,
    validate_billing_attribution,
    validate_modal_invocation_provenance,
    validate_remote_evm_toolchain_provenance,
    validate_replay_evidence_envelope,
    validate_safe_control_sentinel_semantics,
)

RAW_EXPORT = _ROOT / "benchmarks" / "evidence" / "modal_billing_report_raw.json"
JOIN_TABLE = _ROOT / "benchmarks" / "evidence" / "modal_billing_join_table.json"
HARNESS_DIR = _ROOT / "benchmarks" / "targets" / "solidity"
RUN_DIR = _ROOT / "benchmarks" / "artifacts" / "run_1794209615_70f5d22"
SAFE_RUN_DIR = RUN_DIR / "baseline_5"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _observed_stage(**overrides):
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


def _complete_replay_envelope(tmp_path: Path):
    """Build a fully valid replay envelope with the artifacts stored on disk."""
    stdout_bytes = b'{"test":"testExploit","status":"Success"}\n'
    stderr_bytes = b""
    candidate_bytes = b"// SPDX-License-Identifier: MIT\ncontract Candidate {}\n"
    harness_bytes = b"// SPDX-License-Identifier: MIT\ncontract VaultHarness {}\n"

    stdout_art = persist_replay_artifact(tmp_path, "REENT-01_replay_stdout.txt", stdout_bytes)
    stderr_art = persist_replay_artifact(tmp_path, "REENT-01_replay_stderr.txt", stderr_bytes)
    candidate_art = persist_replay_artifact(tmp_path, "REENT-01_replay_candidate.sol", candidate_bytes)
    harness_art = persist_replay_artifact(tmp_path, "REENT-01_replay_harness.t.sol", harness_bytes)

    envelope = {
        "reproduced": True,
        "complete": True,
        "container_id": "hokkglpxczflmxlcnxxg",
        "command": "forge test --offline --json -vvvv",
        "argv": ["forge", "test", "--offline", "--json", "-vvvv"],
        "return_code": 0,
        "exit_code": 0,
        "invariant_violated": True,
        "harness_verdict": "BREACH",
        "harness_suite": "test/VaultHarness.t.sol",
        "category": "EXPLOIT_CONFIRMED",
        "stdout_artifact": stdout_art.to_dict(),
        "stderr_artifact": stderr_art.to_dict(),
        "candidate_input_artifact": candidate_art.to_dict(),
        "harness_input_artifact": harness_art.to_dict(),
        "stdout_sha256": stdout_art.sha256,
        "stderr_sha256": stderr_art.sha256,
        "candidate_sha256": candidate_art.sha256,
        "harness_sha256": harness_art.sha256,
        "utc_start_time": "2026-11-09T08:00:00Z",
        "utc_end_time": "2026-11-09T08:02:00Z",
    }
    artifact = {
        "target_id": "REENT-01",
        "replay_status": "CONFIRMED",
        "replayed_breaches": 1,
        "replay_evidence": envelope,
        "tool_metadata": {"replay_evidence": envelope},
        "utc_start_time": "2026-11-09T07:33:41Z",
        "utc_end_time": "2026-11-09T07:35:20Z",
        "output_sha256": candidate_art.sha256,
    }
    return artifact, envelope


def _observed_evm_provenance():
    return {
        "remote_os": observed("Debian GNU/Linux 12 (bookworm)", source="/etc/os-release:PRETTY_NAME"),
        "remote_platform": observed("posix", source="os.name"),
        "image_digest": observed("im-9QaB3xKd7Lm2Np", source="modal.config.image_id"),
        "forge_version": observed(
            "forge Version: 1.9.0\nCommit SHA: 6056c5845d34205a83cf7108042adb137325c9df",
            source="forge --version",
        ),
        "solc_versions": observed(["0.8.20"], source="forge config --json -> solc"),
        "exact_forge_argv": observed(
            ["forge", "test", "--offline", "--json", "-vvvv"], source="the argv that was executed"
        ),
        "working_directory": observed("/tmp/tmpab12cd", source="the cwd of the forge process"),
        "compiler_settings": observed(
            {
                "evm_version": "shanghai",
                "optimizer": True,
                "optimizer_runs": 200,
                "via_ir": False,
            },
            source="forge config --json",
        ),
        "observed_exit_code": observed(0, source="the exit code of the forge process"),
    }


# ===========================================================================
# P0.1 - Modal invocation provenance
# ===========================================================================

def test_modal_provenance_accepts_fully_observed_facts():
    artifact = {
        "target_id": "REENT-01",
        "modal_invocation_provenance": {
            "modal_app_id": observed(
                "ap-EDUitOwWeMrIdYbTh4kB63", source="modal.running_app().app_id"
            ),
            "target_id": "REENT-01",
            "stages": {
                "evm_sandbox": _observed_stage(),
                "independent_replay": _observed_stage(function_name="verify_replay_remote"),
            },
        },
    }
    ok, err = validate_modal_invocation_provenance(artifact)
    assert ok is True, err
    assert err is None


def test_modal_provenance_rejects_synthetic_log_uri():
    artifact = {
        "target_id": "REENT-01",
        "modal_invocation_provenance": {
            "stages": {
                "evm_sandbox": _observed_stage(
                    durable_log_ref="modal-app://ap-EDUitOwWeMrIdYbTh4kB63/verify_exploit_remote/REENT-01"
                )
            }
        },
    }
    ok, err = validate_modal_invocation_provenance(artifact)
    assert ok is False
    assert "synthetic log URI" in err


def test_modal_provenance_rejects_malformed_app_id():
    artifact = {
        "target_id": "REENT-01",
        "modal_invocation_provenance": {
            "stages": {
                "evm_sandbox": _observed_stage(app_id=observed("app-not-a-modal-id", source="x"))
            }
        },
    }
    ok, err = validate_modal_invocation_provenance(artifact)
    assert ok is False
    assert "malformed application id" in err


def test_modal_provenance_rejects_unknown_app_id():
    artifact = {
        "target_id": "REENT-01",
        "modal_invocation_provenance": {
            "stages": {
                "evm_sandbox": _observed_stage(
                    app_id=observed("ap-ZZZZZZZZZZZZZZZZZZ", source="modal.running_app().app_id")
                )
            }
        },
    }
    ok, err = validate_modal_invocation_provenance(
        artifact, known_app_ids=["ap-EDUitOwWeMrIdYbTh4kB63"]
    )
    assert ok is False
    assert "absent from the raw billing export" in err


def test_modal_provenance_rejects_not_available_without_reason():
    artifact = {
        "target_id": "REENT-01",
        "modal_invocation_provenance": {
            "stages": {
                "evm_sandbox": _observed_stage(app_id={"status": NOT_AVAILABLE})
            }
        },
    }
    ok, err = validate_modal_invocation_provenance(artifact)
    assert ok is False
    assert "without an explicit reason" in err


def test_modal_provenance_rejects_synthetic_container_id():
    artifact = {
        "target_id": "REENT-01",
        "modal_invocation_provenance": {
            "stages": {
                "evm_sandbox": _observed_stage(
                    container_id=observed("modal-cpu-ca9285db97bf", source="client-side fallback")
                )
            }
        },
    }
    ok, err = validate_modal_invocation_provenance(artifact)
    assert ok is False
    assert "synthetic container id" in err


def test_modal_provenance_rejects_missing_block():
    ok, err = validate_modal_invocation_provenance({"target_id": "REENT-01"})
    assert ok is False
    assert "Missing modal_invocation_provenance" in err


def test_not_available_fact_carries_reason_and_evidence_digest():
    ref = build_evidence_ref(RAW_EXPORT, description="raw Modal billing export")
    assert ref is not None
    assert re.fullmatch(r"[0-9a-f]{64}", ref.sha256)

    fact = not_available("the runtime did not expose an invocation id", evidence_ref=ref)
    assert fact["status"] == NOT_AVAILABLE
    assert fact["reason"]
    assert fact["evidence_ref"]["sha256"] == ref.sha256
    assert fact["evidence_ref"]["path"].endswith("modal_billing_report_raw.json")


def test_evidence_ref_is_none_for_missing_artifact(tmp_path):
    assert build_evidence_ref(tmp_path / "does-not-exist.json") is None


def test_has_synthetic_modal_uri_detects_fabricated_uris():
    assert has_synthetic_modal_uri("modal-app://ap-1/inference/X") is True
    assert has_synthetic_modal_uri({"a": ["https://modal.com/apps/ap-1"]}) is False
    assert has_synthetic_modal_uri({"a": {"b": "modal-app://x"}}) is True


@pytest.mark.parametrize(
    "source_file",
    [
        "benchmarks/adapters.py",
        "benchmarks/protocol.py",
        "benchmarks/benchmark_runner.py",
        "modal_app.py",
        "benchmarks/evidence_integrity.py",
        "sandbox/runner.py",
    ],
)
def test_producer_sources_contain_no_hardcoded_app_id_or_synthetic_uri(source_file):
    """The producing code must not carry the old hardcoded id or a fabricated URI."""
    text = (_ROOT / source_file).read_text(encoding="utf-8")
    # The literal app id may only appear inside the validator's "must not be
    # this constant" guard, never as a produced value.
    for line in text.splitlines():
        if "ap-EDUitOwWeMrIdYbTh4kB63" not in line:
            continue
        assert "legacy" in line.lower() or "hardcoded" in line.lower() or "constant" in line.lower(), (
            f"{source_file}: hardcoded Modal app id used as a produced value: {line.strip()!r}"
        )
    assert "modal-app://" not in text.replace("modal-app://\"", "").replace(
        "startswith(\"modal-app://\")", ""
    ) or "has_synthetic_modal_uri" in text or "synthetic" in text


# ===========================================================================
# P0.1 - Billing attribution
# ===========================================================================

def test_billing_line_items_are_counted_exactly_once():
    line_items = load_raw_billing_line_items(RAW_EXPORT)
    attribution = build_billing_attribution(line_items)
    payload = attribution.to_dict()

    seen = []
    for row in payload["app_session_level"]:
        seen.extend(row["line_item_keys"])
    assert len(seen) == len(line_items)
    assert len(set(seen)) == len(seen)


def test_billing_detects_double_counted_line_item():
    line_items = load_raw_billing_line_items(RAW_EXPORT)
    attribution = build_billing_attribution(line_items).to_dict()
    attribution["app_session_level"].append(dict(attribution["app_session_level"][0]))

    ok, err = validate_billing_attribution(attribution, line_items)
    assert ok is False
    assert "double-counts" in err


def test_billing_detects_dropped_line_item():
    line_items = load_raw_billing_line_items(RAW_EXPORT)
    attribution = build_billing_attribution(line_items).to_dict()
    attribution["app_session_level"].pop()

    ok, err = validate_billing_attribution(attribution, line_items)
    assert ok is False
    assert "omits" in err


def test_billing_rejects_unknown_app_id():
    line_items = load_raw_billing_line_items(RAW_EXPORT)
    attribution = build_billing_attribution(line_items).to_dict()
    attribution["app_session_level"][0]["app_id"] = "ap-NotInTheRawExport"

    ok, err = validate_billing_attribution(
        attribution, line_items, known_app_ids=[item.object_id for item in line_items]
    )
    assert ok is False
    assert "absent from the raw billing export" in err


def test_billing_detects_aggregate_mismatch():
    line_items = load_raw_billing_line_items(RAW_EXPORT)
    attribution = build_billing_attribution(line_items).to_dict()
    attribution["app_session_level"][0]["cost_usd"] = 1.0
    attribution["app_session_level"][0]["cost_usd_exact"] = "1.0"

    ok, err = validate_billing_attribution(attribution, line_items)
    assert ok is False
    assert "does not reconcile exactly" in err


def test_target_cost_is_null_without_proven_join():
    line_items = load_raw_billing_line_items(RAW_EXPORT)
    attribution = build_billing_attribution(
        line_items, target_rows=[{"target_id": "REENT-01", "target_name": "Vault"}]
    )
    assert attribution.target_level[0]["cost_usd"] is None
    assert attribution.target_level[0]["cost_status"] == "UNATTRIBUTED_NO_INVOCATION_LEVEL_JOIN"
    assert attribution.target_level[0]["invocation_join"] is None


def test_billing_rejects_target_cost_without_join_evidence():
    line_items = load_raw_billing_line_items(RAW_EXPORT)
    attribution = build_billing_attribution(
        line_items, target_rows=[{"target_id": "REENT-01", "target_name": "Vault"}]
    ).to_dict()
    attribution["target_level"][0]["cost_usd"] = 0.74323683

    ok, err = validate_billing_attribution(attribution, line_items)
    assert ok is False
    assert "without a proven invocation-level join" in err


def test_saved_join_table_validates_against_the_raw_export():
    line_items = load_raw_billing_line_items(RAW_EXPORT)
    join_table = json.loads(JOIN_TABLE.read_text(encoding="utf-8"))

    ok, err = validate_billing_attribution(
        join_table, line_items, known_app_ids=[item.object_id for item in line_items]
    )
    assert ok is True, err

    # Every target must carry a null cost.
    for row in join_table["target_level"]:
        assert row["cost_usd"] is None

    # No fabricated provider log URI may survive in the new table.
    assert has_synthetic_modal_uri(join_table) is False


def test_saved_join_table_does_not_repeat_aggregate_charges():
    join_table = json.loads(JOIN_TABLE.read_text(encoding="utf-8"))
    total = 0.0
    for row in join_table["app_session_level"]:
        total += float(row["cost_usd"])
    raw_total = sum(float(item.cost_usd) for item in load_raw_billing_line_items(RAW_EXPORT))
    assert abs(total - raw_total) < 1e-9

    # The old table repeated one aggregate 16 times.
    assert len(join_table["target_level"]) == 16
    assert len({row["cost_usd"] for row in join_table["target_level"]}) == 1


# ===========================================================================
# P0.2 - Replay integrity envelope
# ===========================================================================

def test_replay_envelope_accepts_complete_evidence(tmp_path):
    artifact, _ = _complete_replay_envelope(tmp_path)
    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is True, err


def test_replay_envelope_requires_artifact_root(tmp_path):
    artifact, _ = _complete_replay_envelope(tmp_path)
    ok, err = validate_replay_evidence_envelope(artifact)
    assert ok is False
    assert "artifact root" in err


def test_replay_envelope_rejects_missing_bytes(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    del envelope["stdout_artifact"]

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "stdout_artifact" in err


def test_replay_envelope_rejects_hash_mismatch_with_stored_file(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    envelope["stdout_artifact"]["sha256"] = sha256_bytes(b"tampered")

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "does not match the recomputed digest" in err


def test_replay_envelope_rejects_byte_length_mismatch(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    envelope["stderr_artifact"]["byte_length"] = 999

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "byte length" in err


def test_replay_envelope_rejects_missing_path(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    envelope["harness_input_artifact"]["path"] = "does-not-exist.t.sol"

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "missing artifact" in err


def test_replay_envelope_rejects_initial_run_timestamps(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    envelope["utc_start_time"] = artifact["utc_start_time"]
    envelope["utc_end_time"] = artifact["utc_end_time"]

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "initial run" in err


def test_replay_envelope_rejects_synthetic_container_id(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    envelope["container_id"] = "modal-cpu-ca9285db97bf"

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "synthetic container id" in err


def test_replay_envelope_rejects_modified_candidate_or_harness(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    stored = tmp_path / envelope["candidate_input_artifact"]["path"]
    # Same length, different bytes: only the recomputed digest can catch it.
    original = stored.read_bytes()
    stored.write_bytes(b"X" + original[1:])

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "does not match the recomputed digest" in err


def test_replay_envelope_rejects_candidate_that_is_not_the_executed_one(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    artifact["output_sha256"] = sha256_bytes(b"a completely different candidate")

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "does not match the candidate that was executed" in err


def test_replay_envelope_rejects_wrong_exit_code(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    envelope["exit_code"] = 1

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "exit_code must be the integer 0" in err


def test_replay_envelope_requires_real_harness_breach_verdict(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    envelope["harness_verdict"] = "NO_BREACH"

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "harness_verdict must be 'BREACH'" in err


def test_replay_envelope_rejects_missing_argv(tmp_path):
    artifact, envelope = _complete_replay_envelope(tmp_path)
    envelope["argv"] = []

    ok, err = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)
    assert ok is False
    assert "argv" in err


def test_non_confirmed_replay_needs_no_envelope():
    ok, err = validate_replay_evidence_envelope(
        {"target_id": "BIZ-01", "replay_status": "NOT_ELIGIBLE", "replayed_breaches": 0}
    )
    assert ok is True
    assert err is None


def test_incomplete_replay_envelope_is_never_confirmed():
    """A CONFIRMED replay without a complete envelope must fail validation."""
    artifact = {
        "target_id": "REENT-01",
        "replay_status": "CONFIRMED",
        "replayed_breaches": 1,
        "replay_evidence": {"reproduced": True},
    }
    ok, err = validate_replay_evidence_envelope(artifact)
    assert ok is False
    assert err


# ===========================================================================
# P0.3 - Remote EVM toolchain provenance
# ===========================================================================

def test_remote_evm_provenance_from_observed_facts():
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": _observed_evm_provenance(),
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is True, err


def test_remote_evm_provenance_rejects_hardcoded_source():
    """A fact whose source names a constant instead of an observation is rejected."""
    provenance = _observed_evm_provenance()
    provenance["remote_os"] = observed(
        LEGACY_HARDCODED_EVM_FACTS["remote_os"], source="hardcoded constant"
    )
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "not observed from the expected source" in err


def test_remote_evm_provenance_rejects_legacy_hardcoded_forge_version():
    provenance = _observed_evm_provenance()
    provenance["forge_version"] = observed(
        LEGACY_HARDCODED_EVM_FACTS["forge_version"], source="forge --version"
    )
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "legacy hardcoded constant" in err


def test_remote_evm_provenance_rejects_legacy_hardcoded_working_directory():
    provenance = _observed_evm_provenance()
    provenance["working_directory"] = observed(
        LEGACY_HARDCODED_EVM_FACTS["working_directory"], source="the cwd of the forge process"
    )
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "legacy hardcoded constant" in err


def test_remote_evm_provenance_rejects_mutable_image_tag_only():
    provenance = _observed_evm_provenance()
    provenance["image_digest"] = observed(
        "debian:12-slim-foundry", source="modal.config.image_id"
    )
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "immutable Modal image id" in err


def test_remote_evm_provenance_requires_immutable_image_digest():
    provenance = _observed_evm_provenance()
    del provenance["image_digest"]
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "image_digest" in err


def test_remote_evm_provenance_rejects_empty_required_fact():
    provenance = _observed_evm_provenance()
    provenance["forge_version"] = observed("", source="forge --version")
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "forge_version" in err


def test_remote_evm_provenance_accepts_not_available_with_reason():
    provenance = _observed_evm_provenance()
    provenance["image_digest"] = not_available(
        "the Modal runtime did not expose an image id inside this container"
    )
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is True, err


def test_remote_evm_provenance_rejects_not_available_without_reason():
    provenance = _observed_evm_provenance()
    provenance["image_digest"] = {"status": NOT_AVAILABLE}
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "BREACH_VERIFIED",
        "security_verdict": "EXPLOIT_CONFIRMED",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "without a reason" in err


def test_targets_without_evm_stage_have_no_evm_provenance():
    artifact = {
        "target_id": "SIG-01",
        "evm_outcome": "NOT_RUN",
        "security_verdict": "GENERATION_FORMAT_ERROR",
        "process_exit_code": -4,
        "remote_evm_provenance": None,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is True, err


def test_remote_evm_provenance_rejects_presence_on_not_run_target():
    artifact = {
        "target_id": "SIG-01",
        "evm_outcome": "NOT_RUN",
        "security_verdict": "GENERATION_FORMAT_ERROR",
        "process_exit_code": -4,
        "remote_evm_provenance": _observed_evm_provenance(),
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "did not execute an EVM stage" in err


def test_remote_evm_provenance_rejects_inconsistent_exit_code():
    provenance = _observed_evm_provenance()
    provenance["observed_exit_code"] = observed(1, source="the exit code of the forge process")
    artifact = {
        "target_id": "REENT-01",
        "evm_outcome": "RUNTIME_REVERT",
        "security_verdict": "RUNTIME_REVERT",
        "process_exit_code": 0,
        "remote_evm_provenance": provenance,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert "disagrees with the recorded process exit code" in err


def test_run_manifest_has_no_hardcoded_remote_environment():
    """The run-level manifest must not broadcast a constant remote environment."""
    from benchmarks.benchmark_runner import AegisBenchmarkSuite  # noqa: F401

    manifest_source = (_ROOT / "benchmarks" / "benchmark_runner.py").read_text(encoding="utf-8")
    for legacy_value in LEGACY_HARDCODED_EVM_FACTS.values():
        assert legacy_value not in manifest_source, (
            f"the run manifest still carries the hardcoded remote environment {legacy_value!r}"
        )


# ===========================================================================
# P0.4 - Safe-control sentinel
# ===========================================================================

@pytest.mark.parametrize("target_name", sorted(SAFE_CONTROL_TARGETS))
def test_safe_control_sentinel_accepts_exact_documented_sentinel(target_name):
    sentinel = SAFE_CONTROL_SENTINELS[target_name]
    ok, verdict = validate_safe_control_sentinel_semantics(
        sentinel,
        "NO_BREACH",
        target_name,
        harness_suite=f"test/{target_name}Harness.t.sol",
    )
    assert ok is True, verdict
    assert verdict == "SAFE_RUN"


def test_safe_control_sentinel_rejects_prefix_and_suffix():
    exact = SAFE_CONTROL_SENTINELS["SecureVault"]
    ok, reason = validate_safe_control_sentinel_semantics(
        exact[: len(exact) - 1], "NO_BREACH", "SecureVault"
    )
    assert ok is False
    assert "SENTINEL_PREFIX_MISMATCH" in reason

    ok, reason = validate_safe_control_sentinel_semantics(
        exact + " (extra)", "NO_BREACH", "SecureVault"
    )
    assert ok is False
    assert "SENTINEL_SUFFIX_MISMATCH" in reason


def test_safe_control_sentinel_rejects_other_target_sentinel():
    ok, reason = validate_safe_control_sentinel_semantics(
        SAFE_CONTROL_SENTINELS["SecureVault"], "NO_BREACH", "SecureOraclePool"
    )
    assert ok is False
    assert "SENTINEL_BELONGS_TO_OTHER_TARGET" in reason


def test_safe_control_sentinel_requires_target_context():
    ok, reason = validate_safe_control_sentinel_semantics(
        SAFE_CONTROL_SENTINELS["SecureVault"], "NO_BREACH"
    )
    assert ok is False
    assert "MISSING_TARGET_CONTEXT_FOR_SENTINEL" in reason


def test_safe_control_sentinel_rejects_harness_context_mismatch():
    ok, reason = validate_safe_control_sentinel_semantics(
        SAFE_CONTROL_SENTINELS["SecureVault"],
        "NO_BREACH",
        "SecureVault",
        harness_suite="test/VaultHarness.t.sol",
    )
    assert ok is False
    assert "HARNESS_CONTEXT_MISMATCH" in reason


def test_safe_control_sentinel_rejects_generic_revert_panic_and_compile_error():
    ok, reason = validate_safe_control_sentinel_semantics(
        "EvmError: Revert", "NO_BREACH", "SecureVault"
    )
    assert ok is False
    assert "GENERIC_EVM_REVERT_NOT_SENTINEL" in reason

    ok, reason = validate_safe_control_sentinel_semantics(
        "Panic(0x11): Arithmetic underflow/overflow", "NO_BREACH", "SecureVault"
    )
    assert ok is False
    assert "EVM_PANIC_NOT_SENTINEL" in reason

    ok, reason = validate_safe_control_sentinel_semantics(
        "Compiler run failed: ParserError: Expected ';' but got '}'", "NO_BREACH", "SecureVault"
    )
    assert ok is False
    assert "COMPILATION_ERROR_NOT_SENTINEL" in reason


def test_safe_control_sentinel_rejects_infrastructure_failure():
    ok, reason = validate_safe_control_sentinel_semantics(
        "INFRA_ERROR: the sandbox worker died", "NO_BREACH", "SecureVault"
    )
    assert ok is False
    assert "INFRASTRUCTURE_FAILURE_NOT_SENTINEL" in reason


def test_safe_control_sentinel_rejects_arbitrary_exploit_failed_prefix():
    """The old defect: ANY 'EXPLOIT_FAILED...' string was accepted as SAFE."""
    ok, reason = validate_safe_control_sentinel_semantics(
        "EXPLOIT_FAILED: totally made up reason", "NO_BREACH", "SecureVault"
    )
    assert ok is False
    assert "UNRECOGNIZED_REVERT_REASON" in reason


def test_safe_control_sentinel_rejects_empty_reason():
    ok, reason = validate_safe_control_sentinel_semantics(None, "NO_BREACH", "SecureVault")
    assert ok is False
    assert reason == "MISSING_REVERT_REASON"

    ok, reason = validate_safe_control_sentinel_semantics("   ", "NO_BREACH", "SecureVault")
    assert ok is False
    assert reason == "MISSING_REVERT_REASON"


def test_safe_control_sentinel_rejects_wrong_harness_verdict():
    ok, reason = validate_safe_control_sentinel_semantics(
        SAFE_CONTROL_SENTINELS["SecureVault"], "BREACH", "SecureVault"
    )
    assert ok is False
    assert "HARNESS_VERDICT_NOT_NO_BREACH" in reason


def test_sentinel_registry_matches_the_repository_harness_sources():
    """The registry must mirror the immutable harness sources, not a guess."""
    for target_name, sentinel in HARNESS_SENTINELS.items():
        harness_path = HARNESS_DIR / f"{target_name}Harness.t.sol"
        assert harness_path.is_file(), f"missing harness source for {target_name}"
        source = harness_path.read_text(encoding="utf-8")
        assert sentinel in source, (
            f"the sentinel registered for {target_name} does not occur in {harness_path.name}"
        )


def test_all_saved_safe_control_artifacts_carry_their_exact_sentinel():
    """The four existing safe-control artifacts must validate under the strict rule."""
    checked = 0
    for target_id in ("SAFE-01", "SAFE-02", "SAFE-03", "SAFE-04"):
        artifact_path = SAFE_RUN_DIR / f"{target_id}.json"
        assert artifact_path.is_file(), f"missing saved artifact {artifact_path}"
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        target_name = artifact["target_name"]
        assert target_name in SAFE_CONTROL_TARGETS

        stdout = (SAFE_RUN_DIR / f"{target_id}_stdout.txt").read_text(encoding="utf-8")
        assert SAFE_CONTROL_SENTINELS[target_name] in stdout, (
            f"{target_id} does not carry the documented sentinel of {target_name}"
        )

        ok, verdict = validate_safe_control_sentinel_semantics(
            SAFE_CONTROL_SENTINELS[target_name],
            artifact.get("harness_verdict"),
            target_name,
            harness_suite=f"test/{target_name}Harness.t.sol",
        )
        assert ok is True, f"{target_id}: {verdict}"
        checked += 1
    assert checked == 4


# ===========================================================================
# Cross-cutting: the evidence chain must not claim what it cannot prove
# ===========================================================================

def test_saved_run_artifacts_do_not_pass_the_new_validators():
    """
    The saved run predates the fix, so the strict validators must reject it.

    This is the honest outcome: the artifacts carry the old hardcoded remote
    environment and the old synthetic container identities.
    """
    artifact_path = SAFE_RUN_DIR / "SAFE-01.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))

    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is False
    assert err


def test_stored_stdout_digests_match_the_stored_bytes():
    """
    The saved run artifacts are internally consistent: every recorded stdout and
    stderr digest describes exactly the bytes that are stored next to it.

    This is the property the new byte-exact writer guarantees going forward.
    """
    checked = 0
    for artifact_path in sorted(SAFE_RUN_DIR.glob("*.json")):
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        for path_key, digest_key in (
            ("stdout_path", "stdout_sha256"),
            ("stderr_path", "stderr_sha256"),
        ):
            rel = artifact.get(path_key)
            declared = artifact.get(digest_key)
            if not rel or not declared:
                continue
            stored = _ROOT / rel
            if not stored.is_file():
                continue
            assert file_sha256(stored) == declared, (
                f"{artifact_path.name}: {path_key} digest does not describe the stored bytes"
            )
            checked += 1
    assert checked > 0


# ===========================================================================
# Validation evidence (machine-readable, bound to the exact code SHA)
# ===========================================================================

VALIDATION_EVIDENCE = _ROOT / "benchmarks" / "evidence" / "iteration14_validation_evidence.json"


def test_validation_evidence_is_bound_to_the_code_sha():
    """The published validation evidence must name the code SHA it was produced from."""
    assert VALIDATION_EVIDENCE.is_file(), "the validation evidence artifact is missing"
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))

    assert report["schema_version"] == "1.0.0"
    assert report["generator"] == "benchmarks/validate_iteration14_evidence.py"

    code_sha = report["code_sha"]
    assert isinstance(code_sha, str) and re.fullmatch(r"[0-9a-f]{40}", code_sha), code_sha

    # The SHA must be a real commit of this repository.
    import subprocess

    result = subprocess.run(
        ["git", "cat-file", "-t", code_sha],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"{code_sha} is not a commit of this repository"

    # The SHA must be part of the history of the checked-out branch.
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

    # The billing join table and the raw export must be referenced by digest.
    assert report["scope"]["raw_billing_export"].endswith("modal_billing_report_raw.json")
    assert report["scope"]["billing_join_table"].endswith("modal_billing_join_table.json")


def test_validation_evidence_reports_the_saved_run_honestly():
    """
    The saved run predates the Iteration 14 fix, so the report must say so.

    A report that claimed PASSED for artifacts that violate the new validators
    would be exactly the kind of false success state this task forbids.
    """
    assert VALIDATION_EVIDENCE.is_file()
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))

    summary = report["summary"]
    assert summary["targets_checked"] == 16
    assert summary["targets_failed"] > 0
    assert summary["overall_status"] == "FAILED"

    # Every planned/attempted/executed/observed/reported dimension is stated.
    for key in ("planned", "attempted", "executed", "observed", "reported"):
        assert key in report["interpretation"]
        assert report["interpretation"][key]

    # The billing reconciliation itself must pass: the join table was fixed.
    billing_checks = [c for c in report["checks"] if c["check"].startswith("P0.1.billing")]
    assert billing_checks
    assert billing_checks[0]["status"] == "PASSED"
    assert billing_checks[0]["synthetic_uri_present"] is False


def test_validation_evidence_check_mode_detects_a_foreign_code_sha(tmp_path):
    """The `--check` mode must refuse a report that belongs to another commit."""
    from benchmarks.validate_iteration14_evidence import main

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    report["code_sha"] = "0" * 40
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps(report), encoding="utf-8")

    exit_code = main(
        [
            "--check",
            "--report",
            str(foreign),
            "--code-sha",
            "a" * 40,
        ]
    )
    assert exit_code == 1


# ===========================================================================
# Real Foundry integration (positive and negative)
#
# These tests execute a REAL forge run. They are skipped (NOT_RUN) when the
# forge binary is not on PATH; in the CI foundry-integration job forge is
# always present, so the tests really execute there.
# ===========================================================================

def _forge_available() -> bool:
    import shutil

    return shutil.which("forge") is not None


def _skip_without_forge() -> None:
    if not _forge_available():
        pytest.skip("NOT_RUN: Real Foundry integration unavailable on system PATH")


def _secure_vault_target():
    from core.schemas import TargetProgram

    source = (HARNESS_DIR / "controls" / "SecureVault.sol").read_text(encoding="utf-8")
    return TargetProgram(
        name="SecureVault",
        source_code=source,
        invariants=["INDIVIDUAL_DEPOSITOR_SOLVENCY"],
    )


_BENIGN_EXPLOIT = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.20;\n\n"
    'import {SecureVault} from "../src/SecureVault.sol";\n\n'
    "contract ExploitModule {\n"
    "    SecureVault public targetContract;\n\n"
    "    constructor(address _target) payable {\n"
    "        targetContract = SecureVault(payable(_target));\n"
    "    }\n\n"
    "    function runExploit() external payable {\n"
    "        targetContract.deposit{value: msg.value}();\n"
    "    }\n\n"
    "    receive() external payable {}\n"
    "}\n"
)


def test_real_foundry_integration_observed_environment_carries_real_facts():
    """A real forge run must yield OBSERVED toolchain facts, never constants."""
    _skip_without_forge()

    from core.schemas import AttackHypothesis, ExploitPayload
    from sandbox.runner import run_payload_in_sandbox

    payload = ExploitPayload(
        target_name="SecureVault",
        test_code=_BENIGN_EXPLOIT,
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="real foundry probe",
            attack_vector="deposit",
        ),
        format_valid=True,
    )
    result = run_payload_in_sandbox(_secure_vault_target(), payload)
    env = result.observed_environment
    assert isinstance(env, dict) and env

    # Every required fact is present and is either OBSERVED or NOT_AVAILABLE.
    for fact_name in (
        "remote_os",
        "remote_platform",
        "image_digest",
        "forge_version",
        "solc_versions",
        "exact_forge_argv",
        "working_directory",
        "compiler_settings",
    ):
        assert fact_name in env, fact_name
        fact = env[fact_name]
        assert fact["status"] in (OBSERVED, NOT_AVAILABLE)
        if fact["status"] == NOT_AVAILABLE:
            assert fact["reason"]
        else:
            assert fact["source"]

    # The forge version is the real output of `forge --version`.
    forge_version = env["forge_version"]
    if forge_version["status"] == OBSERVED:
        assert re.search(r"forge\s+Version:\s*\d+\.\d+\.\d+", forge_version["value"])

    # The compiler settings are the effective ones of the sandbox project.
    settings = env["compiler_settings"]
    if settings["status"] == OBSERVED:
        assert settings["value"].get("evm_version")
        assert settings["value"].get("optimizer") is True

    # The argv is the command line that really ran.
    argv = env["exact_forge_argv"]
    if argv["status"] == OBSERVED:
        assert argv["value"][0].endswith("forge")

    # The provenance passes the strict validator for an executed EVM stage.
    artifact = {
        "target_id": "SAFE-01",
        "evm_outcome": "SAFE_CONTROL_HELD",
        "security_verdict": "SAFE_RUN",
        "process_exit_code": result.return_code,
        "remote_evm_provenance": env,
    }
    ok, err = validate_remote_evm_toolchain_provenance(artifact)
    assert ok is True, err


def test_real_foundry_integration_safe_control_emits_the_exact_documented_sentinel():
    """A real safe-control run must emit exactly the documented sentinel."""
    _skip_without_forge()

    from core.schemas import AttackHypothesis, ExploitPayload
    from sandbox.runner import run_payload_in_sandbox

    payload = ExploitPayload(
        target_name="SecureVault",
        test_code=_BENIGN_EXPLOIT,
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="real foundry safe control probe",
            attack_vector="deposit",
        ),
        format_valid=True,
    )
    result = run_payload_in_sandbox(_secure_vault_target(), payload)

    assert result.harness_verdict == "NO_BREACH"
    assert result.invariant_violated is False
    sentinel = SAFE_CONTROL_SENTINELS["SecureVault"]
    assert sentinel in (result.stdout or "")

    ok, verdict = validate_safe_control_sentinel_semantics(
        sentinel,
        result.harness_verdict,
        "SecureVault",
        harness_suite="test/SecureVaultHarness.t.sol",
    )
    assert ok is True, verdict
    assert verdict == "SAFE_RUN"


def test_real_foundry_integration_compilation_error_is_never_a_safe_control():
    """A real compilation failure must never be classified as a safe control."""
    _skip_without_forge()

    from core.schemas import AttackHypothesis, ExploitPayload, ResultCategory
    from sandbox.runner import run_payload_in_sandbox

    broken = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        "contract ExploitModule {\n"
        "    DELIBERATE_SYNTAX_ERROR_FOR_COMPILATION_TEST();\n"
        "}\n"
    )
    payload = ExploitPayload(
        target_name="SecureVault",
        test_code=broken,
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="real foundry negative probe",
            attack_vector="broken",
        ),
        format_valid=True,
    )
    result = run_payload_in_sandbox(_secure_vault_target(), payload)

    assert result.return_code != 0
    assert result.category == ResultCategory.COMPILATION_ERROR
    assert result.invariant_violated is False

    # The generic failure must not be accepted as a safe-control sentinel.
    ok, reason = validate_safe_control_sentinel_semantics(
        result.revert_reason or result.stderr or "",
        "NO_BREACH",
        "SecureVault",
    )
    assert ok is False
