"""
tests/test_iteration16_evidence_integrity.py
============================================

Iteration 16 (PR #12 follow-up) - per-stage provenance evidence.

The Iteration 16 review named one remaining P0 defect in the producer path:
the evidence bytes did not cover every stage whose facts they were used for.
All four stages (inference, EVM sandbox, independent replay, trajectory
persistence) cited ONE shared file that held the bytes of the EVM and the
replay stage only, and nothing in that file said which stage it belonged to.

Iteration 16 therefore:

* gives every stage its own evidence artifact, containing the exact response
  that stage returned;
* binds every fact to the artifact of its own stage - an EVM artifact can no
  longer back an inference fact;
* distinguishes the kinds of absence honestly: a provider that omitted a
  field, a stage that was never attempted, a stage that returned no runtime
  envelope, and a field this client never asked for. Only the first may claim
  that "the provider did not report" anything.

Every requirement gets a positive test (the honest case must pass) and a set
of negative tests (every way of cheating must fail).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    ABSENCE_CLIENT_NEVER_CAPTURED_FIELD,
    ABSENCE_KINDS,
    ABSENCE_PROVIDER_FIELD_OMITTED,
    ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE,
    ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE,
    ABSENCE_STAGE_NOT_ATTEMPTED,
    MODAL_IDENTITY_FIELDS,
    NOT_AVAILABLE,
    OBSERVED,
    PROVIDER_OMISSION_PHRASE_RE,
    STAGE_EVIDENCE_SCHEMA_VERSION,
    StageResponseCapture,
    build_evidence_ref_from_bytes,
    build_modal_stage_provenance,
    build_stage_evidence_artifact,
    build_stage_identity_facts,
    canonical_json_bytes,
    sha256_bytes,
    validate_modal_invocation_provenance,
    validate_stage_evidence_artifact,
    validate_stage_evidence_binding,
    write_stage_evidence_artifact,
)

VALIDATION_EVIDENCE = _ROOT / "benchmarks" / "evidence" / "iteration16_validation_evidence.json"

APP_ID = "ap-EDUitOwWeMrIdYbTh4kB63"
FUNCTION_CALL_ID = "fc-8Hq2ZpQrVt3Lb"
CONTAINER_ID = "hokkglpxczflmxlcnxxg"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _runtime_identity(**overrides: Any) -> Dict[str, Any]:
    """A runtime-identity envelope exactly as the Modal workers return it."""
    identity = {
        "app_id": {
            "status": OBSERVED,
            "value": APP_ID,
            "source": "modal.running_app().app_id",
        },
        "function_call_id": {
            "status": OBSERVED,
            "value": FUNCTION_CALL_ID,
            "source": "modal.current_function_call_id()",
        },
        "container_id": {
            "status": OBSERVED,
            "value": CONTAINER_ID,
            "source": "MODAL_WORKER_ID of the running container",
        },
    }
    identity.update(overrides)
    return identity


def _capture(
    stage: str,
    *,
    attempted: bool = True,
    executed: bool = True,
    response_received: bool = True,
    provider_response: Any = None,
    runtime_identity: Optional[Dict[str, Any]] = None,
    runtime_identity_source: str = "modal_runtime",
    requested_fields: Any = MODAL_IDENTITY_FIELDS,
) -> StageResponseCapture:
    """Build the capture of one stage."""
    return StageResponseCapture(
        stage=stage,
        attempted=attempted,
        executed=executed,
        response_received=response_received,
        provider_response=provider_response,
        runtime_identity=runtime_identity,
        runtime_identity_source=runtime_identity_source,
        response_source=f"the response of the {stage} stage",
        requested_fields=tuple(requested_fields),
    )


def _provenance_with_captures(
    tmp_path: Path,
    captures: Dict[str, StageResponseCapture],
    target_id: str = "T-01",
) -> Dict[str, Any]:
    """Write one stage artifact per capture and build the matching provenance."""
    stages: Dict[str, Any] = {}
    for name, capture in captures.items():
        _path, ref = write_stage_evidence_artifact(
            tmp_path, capture, target_id=target_id, correlation_id="corr-test"
        )
        stages[name] = build_modal_stage_provenance(
            function_name=f"fn_{name}",
            resource="CPU",
            attempted=capture.attempted,
            evidence_ref=ref,
            **build_stage_identity_facts(capture, evidence_ref=ref),
        )

    evm_stage = stages.get("evm_sandbox")
    run_app_id = (
        evm_stage["app_id"]
        if isinstance(evm_stage, dict)
        else {"status": OBSERVED, "value": APP_ID, "source": "the EVM sandbox stage"}
    )

    return {
        "target_id": target_id,
        "modal_invocation_provenance": {
            "modal_app_id": run_app_id,
            "target_id": target_id,
            "correlation_id": "corr-test",
            "stages": stages,
        },
    }


def _four_stage_captures() -> Dict[str, StageResponseCapture]:
    """The four stages in the four different situations of the review."""
    return {
        "inference": _capture(
            "inference",
            provider_response={"test_code": "contract ExploitModule {}"},
            runtime_identity=None,
        ),
        "evm_sandbox": _capture(
            "evm_sandbox",
            provider_response={"modal_runtime": _runtime_identity()},
            runtime_identity=_runtime_identity(),
        ),
        "independent_replay": _capture(
            "independent_replay",
            provider_response={"modal_runtime": _runtime_identity()},
            runtime_identity=_runtime_identity(),
        ),
        "trajectory_persistence": _capture(
            "trajectory_persistence",
            provider_response="/vol/models/trajectories/traj_1.json",
            runtime_identity=None,
            runtime_identity_source="",
            requested_fields=(),
        ),
    }


# ===========================================================================
# 1) The producer writes one evidence artifact per stage
# ===========================================================================

def _install_producer_mocks(monkeypatch) -> None:
    """
    Install faithful worker responses for the Modal producer path.

    The responses have the shape the real workers return: the EVM worker
    answers without a runtime-identity envelope, the replay worker answers
    with a full one and with the byte-exact replay artifacts, and the
    persistence worker answers with the stored path only.
    """
    import base64

    import modal_app
    from benchmarks.adapters import FullAegisRLVRBaselineAdapter

    monkeypatch.setattr(
        FullAegisRLVRBaselineAdapter, "check_availability", lambda self: (True, None)
    )

    def mock_verify_exploit_remote(target_dict, payload_dict):
        return {
            "target_name": target_dict["name"],
            "vulnerability_type": "ReentrancyDrain",
            "poc_code": payload_dict.get("test_code", ""),
            "category": "INVARIANT_BREACH_UNREPLAYED",
            "reward_score": 0.5,
            "reward_components": {},
            "is_verified": False,
            "reproducible": False,
            "feedback": "Remote EVM invariant breach achieved",
        }

    def mock_verify_replay_remote(target_dict, payload_dict):
        candidate = (payload_dict.get("test_code") or "").encode("utf-8")
        harness = b"// repository-owned harness\ncontract VaultHarness {}\n"
        stdout = b'{"test/VaultHarness.t.sol:testExploit":{"status":"Success","reason":null}}\n'
        return {
            "reproduced": True,
            "container_id": CONTAINER_ID,
            "modal_runtime": _runtime_identity(),
            "command": "forge test --offline --json -vvvv",
            "argv": ["forge", "test", "--offline", "--json", "-vvvv"],
            "return_code": 0,
            "exit_code": 0,
            "harness_verdict": "BREACH",
            "harness_suite": "test/VaultHarness.t.sol",
            "invariant_violated": True,
            "category": "EXPLOIT_CONFIRMED",
            "stdout_b64": base64.b64encode(stdout).decode("ascii"),
            "stderr_b64": base64.b64encode(b"").decode("ascii"),
            "candidate_b64": base64.b64encode(candidate).decode("ascii"),
            "harness_b64": base64.b64encode(harness).decode("ascii"),
            "utc_start_time": "2026-11-09T03:17:41Z",
            "utc_end_time": "2026-11-09T03:19:20Z",
        }

    monkeypatch.setattr(
        modal_app.verify_exploit_remote, "remote", mock_verify_exploit_remote
    )
    monkeypatch.setattr(
        modal_app.verify_replay_remote, "remote", mock_verify_replay_remote
    )
    monkeypatch.setattr(
        modal_app.record_trajectory_remote,
        "remote",
        lambda traj_dict: "/vol/models/trajectories/traj_1.json",
    )


def _run_producer(tmp_path):
    """Run the producer against the faithful worker responses."""
    from benchmarks.adapters import FullAegisRLVRBaselineAdapter
    from benchmarks.protocol import BenchmarkDataset
    from core.schemas import AttackHypothesis, ExploitPayload

    dataset = BenchmarkDataset()
    vault_target = [t for t in dataset.get_public_targets() if t.target_name == "Vault"][0]
    dummy_payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="Trace",
            attack_vector="Drain",
        ),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        format_valid=True,
    )
    adapter = FullAegisRLVRBaselineAdapter(candidate_generator=lambda prog: dummy_payload)
    return adapter.execute_target(vault_target, replay_artifact_dir=tmp_path)


def test_iteration16_producer_writes_one_evidence_artifact_per_stage(monkeypatch, tmp_path):
    """Every stage of a real producer run gets its own evidence file."""
    _install_producer_mocks(monkeypatch)
    artifact = _run_producer(tmp_path)

    provenance = artifact.tool_metadata.get("modal_invocation_provenance")
    assert isinstance(provenance, dict), "the producer must record the invocation provenance"

    stages = provenance.get("stages")
    assert set(stages) == {
        "inference",
        "evm_sandbox",
        "independent_replay",
        "trajectory_persistence",
    }

    # One artifact per stage, each declaring the stage it belongs to.
    for stage_name in stages:
        artifact_path = tmp_path / f"REENT-01_stage_evidence_{stage_name}.json"
        assert artifact_path.is_file(), f"the {stage_name} stage has no evidence artifact"
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
        assert payload["stage"] == stage_name
        assert payload["schema_version"] == STAGE_EVIDENCE_SCHEMA_VERSION

    # The old shared artifact is gone: it could back any stage.
    assert not (tmp_path / "REENT-01_modal_provenance_evidence.json").exists()


def test_iteration16_producer_binds_every_fact_to_its_own_stage(monkeypatch, tmp_path):
    """A fact may only cite the artifact of the stage it belongs to."""
    _install_producer_mocks(monkeypatch)
    artifact = _run_producer(tmp_path)

    provenance = artifact.tool_metadata["modal_invocation_provenance"]
    stages = provenance["stages"]

    for stage_name, stage in stages.items():
        stage_ref = stage.get("evidence_ref")
        assert stage_ref, f"the {stage_name} stage has no evidence reference"
        assert stage_ref["path"] == f"REENT-01_stage_evidence_{stage_name}.json"
        for key in MODAL_IDENTITY_FIELDS:
            fact = stage[key]
            if fact.get("status") == NOT_AVAILABLE:
                assert fact["evidence_ref"]["path"] == stage_ref["path"], (
                    f"the {stage_name}.{key} fact cites the evidence of another stage"
                )

    # The validator accepts what the producer wrote.
    ok, err = validate_modal_invocation_provenance(
        {
            "target_id": "REENT-01",
            "modal_invocation_provenance": provenance,
        },
        evidence_root=tmp_path,
    )
    assert ok is True, err


def test_iteration16_producer_records_honest_absence_for_every_stage(monkeypatch, tmp_path):
    """Each stage states the kind of absence that actually occurred."""
    _install_producer_mocks(monkeypatch)
    artifact = _run_producer(tmp_path)

    stages = artifact.tool_metadata["modal_invocation_provenance"]["stages"]

    # The inference stage never ran as a Modal stage in this run.
    inference = stages["inference"]
    assert inference["attempted"] is False
    for key in MODAL_IDENTITY_FIELDS:
        fact = inference[key]
        assert fact["status"] == NOT_AVAILABLE
        assert fact["absence_kind"] == ABSENCE_STAGE_NOT_ATTEMPTED

    # The EVM worker answered without a runtime-identity envelope.
    evm = stages["evm_sandbox"]
    for key in MODAL_IDENTITY_FIELDS:
        fact = evm[key]
        assert fact["status"] == NOT_AVAILABLE
        assert fact["absence_kind"] == ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE

    # The replay worker answered with a full runtime identity.
    replay = stages["independent_replay"]
    for key in MODAL_IDENTITY_FIELDS:
        assert replay[key]["status"] == OBSERVED

    # The persistence worker answers with a path; this client never asked for
    # a runtime identity there.
    persistence = stages["trajectory_persistence"]
    assert persistence["attempted"] is True
    for key in MODAL_IDENTITY_FIELDS:
        fact = persistence[key]
        assert fact["status"] == NOT_AVAILABLE
        assert fact["absence_kind"] == ABSENCE_CLIENT_NEVER_CAPTURED_FIELD

    # Only a provider omission may blame the provider.
    for stage_name, stage in stages.items():
        for key in MODAL_IDENTITY_FIELDS:
            fact = stage[key]
            if fact.get("status") != NOT_AVAILABLE:
                continue
            if fact.get("absence_kind") != ABSENCE_PROVIDER_FIELD_OMITTED:
                assert not PROVIDER_OMISSION_PHRASE_RE.search(fact["reason"]), (
                    f"the {stage_name}.{key} fact blames the provider for a field the provider "
                    "was never asked about"
                )


# ===========================================================================
# 2) The stage and its evidence must correspond
# ===========================================================================

def test_iteration16_stage_evidence_binding_accepts_the_honest_case(tmp_path):
    """The four stages with their own artifacts pass."""
    artifact = _provenance_with_captures(tmp_path, _four_stage_captures())
    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is True, err


def test_iteration16_stage_label_must_match_the_stage(tmp_path):
    """An artifact of another stage cannot back this stage."""
    captures = _four_stage_captures()
    artifact = _provenance_with_captures(tmp_path, captures)

    # Replace the inference artifact by the EVM one, keeping the digest valid.
    evm_ref = artifact["modal_invocation_provenance"]["stages"]["evm_sandbox"]["evidence_ref"]
    inference_stage = artifact["modal_invocation_provenance"]["stages"]["inference"]
    inference_stage["evidence_ref"] = evm_ref
    for key in MODAL_IDENTITY_FIELDS:
        fact = inference_stage[key]
        if fact.get("status") == NOT_AVAILABLE:
            fact["evidence_ref"] = evm_ref

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "declares the stage" in err


def test_iteration16_mislabelled_stage_artifact_is_rejected(tmp_path):
    """An artifact that carries another stage's bytes under its own label fails."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity()},
        runtime_identity=_runtime_identity(),
    )
    artifact_payload = build_stage_evidence_artifact(
        capture, target_id="T-01", correlation_id="corr-test"
    )
    # The bytes are the EVM bytes, but the file claims to be the inference stage.
    artifact_payload["stage"] = "inference"
    data = json.dumps(
        artifact_payload, indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    (tmp_path / "T-01_stage_evidence_inference.json").write_bytes(data)
    ref = build_evidence_ref_from_bytes(
        "T-01_stage_evidence_inference.json", data, description="mislabelled"
    )

    inference_capture = _capture(
        "inference",
        provider_response={"test_code": "contract ExploitModule {}"},
        runtime_identity=None,
    )
    stage = build_modal_stage_provenance(
        function_name="fn_inference",
        resource="H100",
        attempted=True,
        evidence_ref=ref,
        **build_stage_identity_facts(inference_capture, evidence_ref=ref),
    )
    artifact = {
        "target_id": "T-01",
        "modal_invocation_provenance": {
            "modal_app_id": {
                "status": OBSERVED,
                "value": APP_ID,
                "source": "modal.running_app().app_id",
            },
            "target_id": "T-01",
            "correlation_id": "corr-test",
            "stages": {"inference": stage},
        },
    }

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "holds no absence record" in err


def test_iteration16_inference_fact_cannot_reference_the_evm_artifact(tmp_path):
    """The core defect of Iteration 15 must be impossible now."""
    artifact = _provenance_with_captures(tmp_path, _four_stage_captures())
    stages = artifact["modal_invocation_provenance"]["stages"]
    evm_ref = stages["evm_sandbox"]["evidence_ref"]

    inference_stage = stages["inference"]
    for key in MODAL_IDENTITY_FIELDS:
        inference_stage[key]["evidence_ref"] = evm_ref

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "evidence of another stage" in err


def test_iteration16_persistence_fact_cannot_reference_the_replay_artifact(tmp_path):
    """A persistence fact may not cite the replay bytes."""
    artifact = _provenance_with_captures(tmp_path, _four_stage_captures())
    stages = artifact["modal_invocation_provenance"]["stages"]
    replay_ref = stages["independent_replay"]["evidence_ref"]

    persistence_stage = stages["trajectory_persistence"]
    for key in MODAL_IDENTITY_FIELDS:
        persistence_stage[key]["evidence_ref"] = replay_ref

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "evidence of another stage" in err


def test_iteration16_missing_stage_artifact_is_rejected(tmp_path):
    """A stage whose evidence file is gone is rejected."""
    artifact = _provenance_with_captures(tmp_path, _four_stage_captures())
    (tmp_path / "T-01_stage_evidence_evm_sandbox.json").unlink()

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "missing artifact" in err


def test_iteration16_tampered_stage_evidence_bytes_are_rejected(tmp_path):
    """The digest of the stage artifact is validated against the stored bytes."""
    artifact = _provenance_with_captures(tmp_path, _four_stage_captures())
    path = tmp_path / "T-01_stage_evidence_evm_sandbox.json"

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is True, err

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["provider_response"]["modal_runtime"]["app_id"]["value"] = "ap-forged"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "does not match the digest of the referenced bytes" in err


def test_iteration16_stage_evidence_path_cannot_escape_the_root(tmp_path):
    """The stage evidence must stay inside the evidence root."""
    artifact = _provenance_with_captures(tmp_path, _four_stage_captures())
    stages = artifact["modal_invocation_provenance"]["stages"]
    outside = dict(stages["evm_sandbox"]["evidence_ref"])
    outside["path"] = "../outside.json"
    stages["evm_sandbox"]["evidence_ref"] = outside

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "not a relative path inside the evidence root" in err


def test_iteration16_stage_evidence_ref_is_digest_verified(tmp_path):
    """The reference of a stage describes exactly the bytes on disk."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity()},
        runtime_identity=_runtime_identity(),
    )
    path, ref = write_stage_evidence_artifact(
        tmp_path, capture, target_id="T-01", correlation_id="corr-test"
    )
    assert ref["sha256"] == sha256_bytes(path.read_bytes())
    assert ref["byte_length"] == path.stat().st_size


# ===========================================================================
# 3) The kinds of absence
# ===========================================================================

def test_iteration16_absence_kinds_are_distinguishable(tmp_path):
    """Every kind of absence is produced in the situation it describes."""
    provider_omitted = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": {"app_id": _runtime_identity()["app_id"]}},
        runtime_identity={"app_id": _runtime_identity()["app_id"]},
    )
    not_attempted = _capture(
        "independent_replay",
        attempted=False,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    no_envelope = _capture(
        "inference",
        provider_response={"test_code": "contract ExploitModule {}"},
        runtime_identity=None,
    )
    never_captured = _capture(
        "trajectory_persistence",
        provider_response="/vol/models/trajectories/traj_1.json",
        runtime_identity=None,
        runtime_identity_source="",
        requested_fields=(),
    )
    failed = _capture(
        "independent_replay",
        attempted=True,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )

    expectations = {
        "evm_sandbox": (provider_omitted, ABSENCE_PROVIDER_FIELD_OMITTED),
        "independent_replay": (not_attempted, ABSENCE_STAGE_NOT_ATTEMPTED),
        "inference": (no_envelope, ABSENCE_STAGE_EXECUTED_NO_RUNTIME_ENVELOPE),
        "trajectory_persistence": (never_captured, ABSENCE_CLIENT_NEVER_CAPTURED_FIELD),
    }
    for stage_name, (capture, expected_kind) in expectations.items():
        facts = build_stage_identity_facts(capture)
        kinds = {
            fact.get("absence_kind")
            for fact in facts.values()
            if fact.get("status") == NOT_AVAILABLE
        }
        assert expected_kind in kinds, f"{stage_name}: {kinds}"
        assert expected_kind in ABSENCE_KINDS

    failed_facts = build_stage_identity_facts(failed)
    assert all(
        fact["absence_kind"] == ABSENCE_STAGE_ATTEMPT_FAILED_NO_RESPONSE
        for fact in failed_facts.values()
    )


def test_iteration16_absence_kind_must_match_the_artifact_record(tmp_path):
    """The fact and its own evidence must agree about the kind of absence."""
    capture = _capture(
        "independent_replay",
        attempted=False,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    _path, ref = write_stage_evidence_artifact(
        tmp_path, capture, target_id="T-01", correlation_id="corr-test"
    )
    stage = build_modal_stage_provenance(
        function_name="fn_independent_replay",
        resource="CPU",
        attempted=False,
        evidence_ref=ref,
        **build_stage_identity_facts(capture, evidence_ref=ref),
    )
    # The fact claims a provider omission although the stage never ran.
    stage["app_id"]["absence_kind"] = ABSENCE_PROVIDER_FIELD_OMITTED

    artifact = {
        "target_id": "T-01",
        "modal_invocation_provenance": {
            "modal_app_id": {
                "status": OBSERVED,
                "value": APP_ID,
                "source": "modal.running_app().app_id",
            },
            "target_id": "T-01",
            "correlation_id": "corr-test",
            "stages": {"independent_replay": stage},
        },
    }

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "while its own evidence records" in err


def test_iteration16_not_attempted_may_not_claim_provider_omission(tmp_path):
    """A stage that never ran cannot be refused by the provider."""
    capture = _capture(
        "independent_replay",
        attempted=False,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    _path, ref = write_stage_evidence_artifact(
        tmp_path, capture, target_id="T-01", correlation_id="corr-test"
    )
    facts = build_stage_identity_facts(capture, evidence_ref=ref)
    facts["app_id"]["reason"] = "the provider did not report the application id"

    stage = build_modal_stage_provenance(
        function_name="fn_independent_replay",
        resource="CPU",
        attempted=False,
        evidence_ref=ref,
        **facts,
    )
    artifact = {
        "target_id": "T-01",
        "modal_invocation_provenance": {
            "modal_app_id": {
                "status": OBSERVED,
                "value": APP_ID,
                "source": "modal.running_app().app_id",
            },
            "target_id": "T-01",
            "correlation_id": "corr-test",
            "stages": {"independent_replay": stage},
        },
    }

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "never requested from the provider" in err


def test_iteration16_not_attempted_reason_may_not_claim_the_provider_omitted_the_field(tmp_path):
    """The artifact itself may not blame the provider for an unasked field."""
    capture = _capture(
        "independent_replay",
        attempted=False,
        executed=False,
        response_received=False,
        provider_response=None,
        runtime_identity=None,
    )
    artifact_payload = build_stage_evidence_artifact(
        capture, target_id="T-01", correlation_id="corr-test"
    )
    artifact_payload["absence_records"][0]["reason"] = (
        "the provider did not report the application id"
    )
    data = json.dumps(
        artifact_payload, indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    (tmp_path / "T-01_stage_evidence_independent_replay.json").write_bytes(data)
    ref = build_evidence_ref_from_bytes(
        "T-01_stage_evidence_independent_replay.json", data, description="stage evidence"
    )

    ok, err = validate_stage_evidence_artifact(
        json.loads(data.decode("utf-8")), expected_stage="independent_replay"
    )
    assert ok is False
    assert "the provider was never asked" in err

    # The same is true through the full validator.
    stage = build_modal_stage_provenance(
        function_name="fn_independent_replay",
        resource="CPU",
        attempted=False,
        evidence_ref=ref,
        **build_stage_identity_facts(capture, evidence_ref=ref),
    )
    artifact = {
        "target_id": "T-01",
        "modal_invocation_provenance": {
            "modal_app_id": {
                "status": OBSERVED,
                "value": APP_ID,
                "source": "modal.running_app().app_id",
            },
            "target_id": "T-01",
            "correlation_id": "corr-test",
            "stages": {"independent_replay": stage},
        },
    }
    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "the provider was never asked" in err


def test_iteration16_provider_omission_wording_is_allowed_only_for_omission(tmp_path):
    """A real provider omission may be phrased as such."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": {"app_id": _runtime_identity()["app_id"]}},
        runtime_identity={"app_id": _runtime_identity()["app_id"]},
    )
    facts = build_stage_identity_facts(capture)
    for fact in facts.values():
        if fact.get("status") == NOT_AVAILABLE:
            assert fact["absence_kind"] == ABSENCE_PROVIDER_FIELD_OMITTED
            assert "the provider's response" in fact["reason"]


# ===========================================================================
# 4) The captured response itself
# ===========================================================================

def test_iteration16_stage_artifact_records_the_returned_payload_bytes(tmp_path):
    """The artifact holds the returned payload and its digest."""
    provider_response = {
        "modal_runtime": _runtime_identity(),
        "sandbox_stdout": "Ran 1 test for test/VaultHarness.t.sol",
    }
    capture = _capture(
        "evm_sandbox",
        provider_response=provider_response,
        runtime_identity=_runtime_identity(),
    )
    path, _ref = write_stage_evidence_artifact(
        tmp_path, capture, target_id="T-01", correlation_id="corr-test"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["provider_response"] == provider_response
    metadata = payload["provider_response_metadata"]
    assert metadata["response_sha256"] == sha256_bytes(canonical_json_bytes(provider_response))
    assert metadata["response_byte_length"] == len(canonical_json_bytes(provider_response))
    assert metadata["response_source"]
    assert payload["attempted"] is True
    assert payload["executed"] is True
    assert payload["response_received"] is True
    assert payload["runtime_envelope_received"] is True
    assert payload["runtime_identity"] == _runtime_identity()


def test_iteration16_tampered_provider_response_is_rejected(tmp_path):
    """Bytes that were altered inside the artifact are detected."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity()},
        runtime_identity=_runtime_identity(),
    )
    artifact_payload = build_stage_evidence_artifact(
        capture, target_id="T-01", correlation_id="corr-test"
    )
    artifact_payload["provider_response"]["modal_runtime"]["app_id"]["value"] = "ap-forged"

    ok, err = validate_stage_evidence_artifact(
        artifact_payload, expected_stage="evm_sandbox"
    )
    assert ok is False
    assert "does not match the payload stored" in err


def test_iteration16_runtime_envelope_must_come_from_the_returned_payload(tmp_path):
    """The envelope must be the one the returned payload carries."""
    capture = _capture(
        "evm_sandbox",
        provider_response={"modal_runtime": _runtime_identity()},
        runtime_identity=_runtime_identity(),
    )
    artifact_payload = build_stage_evidence_artifact(
        capture, target_id="T-01", correlation_id="corr-test"
    )
    # The envelope is swapped, but its own digest is kept consistent, so only
    # the relation to the returned payload can give the tampering away.
    artifact_payload["runtime_identity"] = _runtime_identity(container_id="other-container")
    artifact_payload["provider_response_metadata"]["runtime_identity_sha256"] = sha256_bytes(
        canonical_json_bytes(artifact_payload["runtime_identity"])
    )

    ok, err = validate_stage_evidence_artifact(
        artifact_payload, expected_stage="evm_sandbox"
    )
    assert ok is False
    assert "not the one the returned payload carries" in err


def test_iteration16_stage_binding_requires_a_stage_artifact(tmp_path):
    """A stage that claims a missing field without evidence is rejected."""
    stage = build_modal_stage_provenance(
        function_name="fn_evm_sandbox",
        resource="CPU",
        attempted=True,
        app_id={
            "status": NOT_AVAILABLE,
            "value": None,
            "reason": "the provider's response does not contain the application id",
            "absence_kind": ABSENCE_PROVIDER_FIELD_OMITTED,
        },
        function_call_id={
            "status": OBSERVED,
            "value": FUNCTION_CALL_ID,
            "source": "modal.current_function_call_id()",
        },
        container_id={
            "status": OBSERVED,
            "value": CONTAINER_ID,
            "source": "MODAL_WORKER_ID of the running container",
        },
    )
    ok, err = validate_stage_evidence_binding(
        "evm_sandbox", stage, evidence_root=tmp_path
    )
    assert ok is False
    assert "without an evidence reference" in err


def test_iteration16_run_level_app_id_is_bound_to_the_evm_stage(tmp_path):
    """The run-level application id is the one the EVM stage reported."""
    artifact = _provenance_with_captures(tmp_path, _four_stage_captures())
    provenance = artifact["modal_invocation_provenance"]
    evm_stage = provenance["stages"]["evm_sandbox"]

    assert provenance["modal_app_id"] == evm_stage["app_id"]

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is True, err


def test_iteration16_run_level_app_id_cannot_reference_another_stage(tmp_path):
    """The run-level application id may not cite the replay bytes."""
    artifact = _provenance_with_captures(tmp_path, _four_stage_captures())
    provenance = artifact["modal_invocation_provenance"]
    replay_ref = provenance["stages"]["independent_replay"]["evidence_ref"]
    provenance["modal_app_id"] = {
        "status": NOT_AVAILABLE,
        "value": None,
        "reason": "the provider's response does not contain the application id",
        "absence_kind": ABSENCE_PROVIDER_FIELD_OMITTED,
        "evidence_ref": replay_ref,
    }

    ok, err = validate_modal_invocation_provenance(artifact, evidence_root=tmp_path)
    assert ok is False
    assert "references the evidence of another stage" in err


# ===========================================================================
# 5) Validation artifact and CI
# ===========================================================================

def test_iteration16_validation_evidence_is_bound_to_the_code_sha():
    """The published validation evidence must name the code SHA it came from."""
    assert VALIDATION_EVIDENCE.is_file(), "the Iteration 16 validation evidence is missing"
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))

    assert report["generator"] == "benchmarks/validate_iteration16_evidence.py"

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


def test_iteration16_validation_evidence_reports_the_stage_binding_per_target():
    """The report must check the stage/evidence correspondence per target."""
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    assert report["per_target"], "the report must carry the per-target results"

    for entry in report["per_target"]:
        check = entry["P0.1.stage_evidence_binding"]
        assert check["check"] == "P0.1.stage_evidence_binding"
        assert check["status"] in ("PASSED", "FAILED", "NOT_APPLICABLE")
        if check["status"] == "FAILED":
            assert check["error"], "a failed check must say why"


def test_iteration16_validation_evidence_check_mode_detects_a_foreign_code_sha(tmp_path):
    """The --check mode must refuse a report that belongs to another commit."""
    from benchmarks.validate_iteration16_evidence import main

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    report["code_sha"] = "0" * 40
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps(report), encoding="utf-8")

    exit_code = main(["--check", "--report", str(foreign), "--code-sha", "a" * 40])
    assert exit_code == 1


def test_iteration16_ci_workflow_runs_the_new_suite():
    """CI must execute the Iteration 16 suite and the Iteration 16 validator."""
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "tests/test_iteration16_evidence_integrity.py" in ci
    assert "benchmarks.validate_iteration16_evidence" in ci
