"""
tests/test_replay_timestamp_integrity.py
========================================

The order of the stages of a run is a fact that has to be **provable**.

Two things made it unprovable before this workstream:

* the timestamps of the stages had a resolution of one **second**, so a replay
  that started in the same second as the initial EVM run was indistinguishable
  from it;
* the end of the primary ``evm_sandbox`` stage was never measured. The
  envelope of the replay was compared against the end of the **whole run** -
  a moment that is later than the replay itself and therefore says nothing
  about the order of the two stages.

These tests pin down the fixed behaviour:

* a replay that starts in the same second as the initial run - but after it,
  with its own function-call id - is accepted;
* a replay that reuses the function-call id of the initial run is refused;
* a replay that does not start after the end of the initial EVM run is refused.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from benchmarks.evidence_integrity import (
    persist_replay_artifact,
    validate_replay_evidence_envelope,
)

#: The function-call id of the initial evm_sandbox stage.
EVM_FUNCTION_CALL_ID = "fc-01M7NH5K7CVVA0JN0EJAHXYAVG"

#: The function-call id of the independent replay: a **fresh** invocation.
REPLAY_FUNCTION_CALL_ID = "fc-01M7NH5SRMPS6X3DAJSMC6DXQ4"


def _envelope_with_artifacts(tmp_path: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """A complete replay envelope whose artifacts are really stored on disk."""
    stdout_bytes = b'{"test":"testExploit","status":"Success"}\n'
    stderr_bytes = b""
    candidate_bytes = b"// SPDX-License-Identifier: MIT\ncontract Candidate {}\n"
    harness_bytes = b"// SPDX-License-Identifier: MIT\ncontract VaultHarness {}\n"

    stdout_art = persist_replay_artifact(tmp_path, "REENT-01_replay_stdout.txt", stdout_bytes)
    stderr_art = persist_replay_artifact(tmp_path, "REENT-01_replay_stderr.txt", stderr_bytes)
    candidate_art = persist_replay_artifact(tmp_path, "REENT-01_replay_candidate.sol", candidate_bytes)
    harness_art = persist_replay_artifact(tmp_path, "REENT-01_replay_harness.t.sol", harness_bytes)

    envelope: Dict[str, Any] = {
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
        # The microsecond resolution of the stage timestamps.
        "utc_start_time": "2026-11-18T09:12:33.123456Z",
        "utc_end_time": "2026-11-18T09:12:35.654321Z",
        "function_call_id": REPLAY_FUNCTION_CALL_ID,
    }
    artifact: Dict[str, Any] = {
        "target_id": "REENT-01",
        "replay_status": "CONFIRMED",
        "replayed_breaches": 1,
        "replay_evidence": envelope,
        "tool_metadata": {"replay_evidence": envelope},
        "utc_start_time": "2026-11-18T09:12:30.000000Z",
        "utc_end_time": "2026-11-18T09:12:36.000000Z",
        "output_sha256": candidate_art.sha256,
    }
    return artifact, envelope


def test_a_replay_in_the_same_second_as_the_initial_run_is_accepted(tmp_path: Path):
    """
    The microsecond resolution makes the order of the stages a fact.

    The replay starts in the very same second as the initial EVM run - but
    2.5 seconds after it, and in its own provider invocation.
    """
    artifact, envelope = _envelope_with_artifacts(tmp_path)

    ok, error = validate_replay_evidence_envelope(
        artifact,
        artifact_root=tmp_path,
        evm_sandbox_function_call_id=EVM_FUNCTION_CALL_ID,
        initial_evm_start_utc="2026-11-18T09:12:30.000000Z",
        initial_evm_end_utc="2026-11-18T09:12:31.000000Z",
    )

    assert ok is True, error
    assert envelope["utc_start_time"] > "2026-11-18T09:12:31.000000Z"


def test_a_replay_that_reuses_the_function_call_id_is_refused(tmp_path: Path):
    """
    The replay must have run in a **fresh** invocation of the provider.

    The function-call id of the replay is the anchor of that proof: the same
    id means the same invocation, and the same invocation is not independent.
    """
    artifact, envelope = _envelope_with_artifacts(tmp_path)
    envelope["function_call_id"] = EVM_FUNCTION_CALL_ID

    ok, error = validate_replay_evidence_envelope(
        artifact,
        artifact_root=tmp_path,
        evm_sandbox_function_call_id=EVM_FUNCTION_CALL_ID,
        initial_evm_start_utc="2026-11-18T09:12:30.000000Z",
        initial_evm_end_utc="2026-11-18T09:12:31.000000Z",
    )

    assert ok is False
    assert "function-call id" in (error or "")


def test_a_replay_that_did_not_start_after_the_initial_run_is_refused(tmp_path: Path):
    """
    The comparison is against the end of the **primary** evm_sandbox stage.

    The overall end of the run is later than the replay itself, so it can
    never be the boundary of the comparison.
    """
    artifact, _envelope = _envelope_with_artifacts(tmp_path)

    ok, error = validate_replay_evidence_envelope(
        artifact,
        artifact_root=tmp_path,
        evm_sandbox_function_call_id=EVM_FUNCTION_CALL_ID,
        initial_evm_start_utc="2026-11-18T09:12:30.000000Z",
        # The initial run ended AFTER the replay had started: the replay is
        # not a replay of this run.
        initial_evm_end_utc="2026-11-18T09:12:34.000000Z",
    )

    assert ok is False
    assert "did not start after" in (error or "")


def test_the_order_is_not_proved_without_the_boundary_of_the_initial_run(tmp_path: Path):
    """
    A boundary that cannot be read is a refusal, not a permission.

    The validator does not guess: a boundary that is not a readable ISO-8601
    UTC timestamp cannot prove the order of the stages.
    """
    artifact, _envelope = _envelope_with_artifacts(tmp_path)

    ok, error = validate_replay_evidence_envelope(
        artifact,
        artifact_root=tmp_path,
        evm_sandbox_function_call_id=EVM_FUNCTION_CALL_ID,
        initial_evm_start_utc="2026-11-18T09:12:30.000000Z",
        initial_evm_end_utc="not-a-timestamp",
    )

    assert ok is False
    assert "not comparable" in (error or "")


def test_the_published_evidence_of_the_r4_run_stays_valid(tmp_path: Path):
    """
    The evidence that was published before this workstream stays valid.

    The legacy validators call the envelope validator without the boundary of
    the initial run: the published evidence carries the timestamps of the run
    it recorded, and it is not re-measured.
    """
    artifact, _envelope = _envelope_with_artifacts(tmp_path)
    artifact["replay_evidence"]["utc_start_time"] = "2026-11-17T19:54:09Z"
    artifact["replay_evidence"]["utc_end_time"] = "2026-11-17T19:54:11Z"

    ok, error = validate_replay_evidence_envelope(artifact, artifact_root=tmp_path)

    assert ok is True, error
