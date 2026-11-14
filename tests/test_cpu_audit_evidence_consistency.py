"""
tests/test_cpu_audit_evidence_consistency.py
=============================================

The consistency contract of the evidence of one audit run.

A result of the CPU audit service is a single statement about one execution.
These tests pin down that the fields of this statement agree with each other
and with the reward:

* ``replay_status`` / ``replay_confirmed`` / ``is_verified`` / ``reproducible``;
* the ``verification_result`` that travels with the verdict;
* ``state_delta_verified`` against the state delta it claims to describe;
* the reward against its own components.

They also pin down the fact that the evidence of the three runs that were
recorded BEFORE the fix is rejected by the strict evaluation of the driver:
the contradictions of that evidence are the defect this workstream repairs.
The historical runs are kept - they are the evidence of the defect - but they
are not accepted as a passing run any more.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from benchmarks.run_cpu_audit import _evaluate_expectations
from core.evaluator import evaluate_execution_trace
from core.schemas import (
    AttackHypothesis,
    ExecutionResult,
    ExploitPayload,
    ResultCategory,
)
from core.reward_shaping import RewardComponent

_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = _ROOT / "benchmarks" / "evidence" / "cpu_audit"


def _payload(run_id: str = "run-1") -> ExploitPayload:
    return ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="ReentrancyDrain",
            reasoning_trace="the trace of the test",
            attack_vector="receive()",
        ),
        test_code="contract ExploitModule { function runExploit() external payable {} }",
        run_id=run_id,
    )


def _oracle_evidence(has_real_snapshot: bool = False, state_changed: bool = False) -> Dict[str, Any]:
    """The evidence of the oracle, as the trusted harness produces it."""
    state_delta: Dict[str, Any] = {
        "initial_state": {},
        "final_state": {},
        "has_real_snapshot": has_real_snapshot,
        "state_changed": state_changed,
        "trace_context": {
            "event_emitted": "SecurityInvariantBreached",
            "verified_event": True,
            "invariant_type": "DEPOSITOR_SOLVENCY_COLLAPSE",
            "deficit": 10_000_000_000_000_000_000,
        },
    }
    return {
        "execution_id": "exec_0123abcd",
        "candidate_id": "cand_1",
        "target_id": "Vault",
        "initial_state_hash": "empty_state",
        "final_state_hash": "empty_state",
        "execution_status": "SUCCESS",
        "execution_success": True,
        "gas_used": None,
        "revert_reason": None,
        "logs_reference": ["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        "environment_fingerprint": {
            "target_name": "Vault",
            "solc_version": "0.8.20",
            "execution_time_sec": 0.5,
        },
        "state_delta": state_delta,
    }


def _verification_result(evidence: Dict[str, Any]):
    from core.schemas import VerificationResult

    return VerificationResult(
        execution_success=True,
        invariant_breach=True,
        replay_confirmed=False,
        confidence_status="PROVISIONAL_BREACH",
        evidence=evidence,
        invariant_results=[],
        breached_invariants=["INV-VAULT-01-SOLVENCY"],
    )


def _execution_result(
    *,
    reproducibility_confirmed: bool = False,
    replay_error: str = None,
    has_real_snapshot: bool = False,
    state_changed: bool = False,
) -> ExecutionResult:
    evidence = _oracle_evidence(has_real_snapshot, state_changed)
    return ExecutionResult(
        return_code=0,
        stdout="[PASS] testExploit()",
        stderr="",
        execution_time_sec=0.5,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        invariant_violated=True,
        test_status="Success",
        harness_verdict="BREACH",
        harness_suite="test/VaultHarness.t.sol",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        reproducibility_confirmed=reproducibility_confirmed,
        replay_error=replay_error,
        evidence=evidence,
        verification_result=_verification_result(evidence),
    )


# ---------------------------------------------------------------------------
# 1. A confirmed exploit
# ---------------------------------------------------------------------------


def test_a_confirmed_exploit_is_consistent_in_every_field():
    verdict = evaluate_execution_trace(
        _payload("run-consistent"), _execution_result(reproducibility_confirmed=True)
    )

    assert verdict.category == ResultCategory.EXPLOIT_CONFIRMED
    assert verdict.reward_score == 1.0
    assert verdict.is_verified is True
    assert verdict.reproducible is True
    assert verdict.replay_status == "CONFIRMED"
    assert verdict.replay_confirmed is True
    # The oracle result that travels with the verdict agrees with the verdict.
    assert verdict.verification_result is not None
    assert verdict.verification_result.replay_confirmed is True
    assert verdict.verification_result.confidence_status == "CONFIRMED"
    # The replay credit is there exactly once, and the reward is its sum.
    assert verdict.reward_components[RewardComponent.REPLAY.value] > 0
    total = sum(verdict.reward_components.values()) + verdict.reward_penalty
    assert abs(total - verdict.reward_score) < 1e-9


def test_the_verdict_belongs_to_the_run_that_produced_it():
    verdict = evaluate_execution_trace(
        _payload("cpu-audit-20261114-vault"), _execution_result(reproducibility_confirmed=True)
    )
    assert verdict.run_id == "cpu-audit-20261114-vault"


# ---------------------------------------------------------------------------
# 2. A breach that was not replayed
# ---------------------------------------------------------------------------


def test_an_unreplayed_breach_never_claims_a_confirmed_exploit():
    verdict = evaluate_execution_trace(
        _payload("run-unreplayed"), _execution_result(reproducibility_confirmed=False)
    )

    assert verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert verdict.reward_score == 0.5
    assert verdict.is_verified is False
    assert verdict.reproducible is False
    assert verdict.replay_status == "FAILED"
    assert verdict.replay_confirmed is False
    assert verdict.verification_result.replay_confirmed is False
    assert verdict.verification_result.confidence_status == "PROVISIONAL_BREACH"
    assert verdict.reward_components.get(RewardComponent.REPLAY.value, 0.0) == 0.0


def test_a_replay_that_failed_for_infrastructure_is_not_an_unreplayed_breach():
    """
    A replay that never ran is an infrastructure failure, not a breach.

    Reporting it as an unreplayed breach would claim that the exploit was
    observed and merely not reproduced - while nothing was observed at all.
    """
    verdict = evaluate_execution_trace(
        _payload("run-infra"),
        _execution_result(reproducibility_confirmed=False, replay_error="TimeoutError: the EVM did not answer"),
    )

    assert verdict.category == ResultCategory.INFRA_ERROR
    assert verdict.reward_score == 0.0
    assert verdict.is_verified is False
    assert verdict.reproducible is False
    assert verdict.replay_status == "INFRA_ERROR"
    assert verdict.replay_confirmed is False


# ---------------------------------------------------------------------------
# 3. The state delta
# ---------------------------------------------------------------------------


def test_a_state_delta_without_a_snapshot_is_not_claimed_as_verified():
    """
    The trusted harness proves a breach through an event, not a snapshot.

    There is no state delta to verify in that case, and the verdict says so.
    """
    verdict = evaluate_execution_trace(
        _payload("run-event"),
        _execution_result(reproducibility_confirmed=True, has_real_snapshot=False),
    )

    assert verdict.state_delta_verified is False
    assert verdict.breach_evidence_basis == "trusted_harness_event"


def test_a_real_and_changed_state_snapshot_is_claimed_as_verified():
    verdict = evaluate_execution_trace(
        _payload("run-snapshot"),
        _execution_result(reproducibility_confirmed=True, has_real_snapshot=True, state_changed=True),
    )

    assert verdict.state_delta_verified is True
    assert verdict.breach_evidence_basis == "verified_state_snapshot"


# ---------------------------------------------------------------------------
# 4. The historical evidence of the three runs before the fix
# ---------------------------------------------------------------------------


def _historical_evidence_files() -> list:
    if not EVIDENCE_DIR.is_dir():
        return []
    return sorted(EVIDENCE_DIR.glob("*_evidence.json"))


def _was_produced_by_the_fixed_service(evidence: Dict[str, Any]) -> bool:
    """
    Whether the run was recorded by the fixed service.

    The fixed service writes a self-check of its own result into the result
    (``consistency``); the runs that were recorded before the fix do not have
    it. The distinction is read from the artifact, not from its name.
    """
    vulnerable = (evidence.get("results") or {}).get("vulnerable_target") or {}
    return "consistency" in vulnerable


def _field_contradictions(result: Dict[str, Any]) -> list:
    """
    The contradictions between the fields of one verdict.

    The check is deliberately independent of the expectation list of the
    driver: it reads the fields of the verdict itself, so it stays meaningful
    when the criteria of the end-to-end test grow.
    """
    verdict = result.get("verdict") or {}
    if not verdict:
        return []
    contradictions = []
    if verdict.get("category") == "EXPLOIT_CONFIRMED":
        if verdict.get("replay_status") != "CONFIRMED":
            contradictions.append("replay_status")
        if verdict.get("is_verified") is not True:
            contradictions.append("is_verified")
        if verdict.get("reproducible") is not True:
            contradictions.append("reproducible")
        if verdict.get("replay_confirmed") is not True:
            contradictions.append("replay_confirmed")
        verification = verdict.get("verification_result") or {}
        if verification.get("replay_confirmed") is not True:
            contradictions.append("verification_result.replay_confirmed")
    state_delta = ((verdict.get("evidence") or {}).get("state_delta")) or {}
    if bool(verdict.get("state_delta_verified")) != bool(
        state_delta.get("has_real_snapshot") and state_delta.get("state_changed")
    ):
        contradictions.append("state_delta_verified")
    return contradictions


@pytest.mark.parametrize("evidence_path", _historical_evidence_files())
def test_every_recorded_run_is_free_of_field_contradictions(evidence_path: Path):
    """
    A recorded run must not contradict itself.

    The runs that were recorded **before** the fix did: they claimed a
    confirmed exploit while their own fields said that the replay was never
    confirmed. They are kept as the evidence of the defect, so the
    contradiction is expected there and only there.
    """
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    results = evidence.get("results") or {}
    contradictions = _field_contradictions(results.get("vulnerable_target") or {})

    if _was_produced_by_the_fixed_service(evidence):
        assert not contradictions, (
            f"{evidence_path.name} contradicts itself: {contradictions}"
        )
    else:
        assert contradictions, (
            f"{evidence_path.name} was expected to carry the contradiction of the "
            "defect - it does not, so the historical evidence changed"
        )


def test_the_newest_recorded_run_passes_the_strict_evaluation():
    """
    The newest run is the one of the fixed service, and it has to be good.

    The strict criteria of the driver are applied to the recorded evidence,
    so the artifact and the criteria cannot drift apart.
    """
    files = _historical_evidence_files()
    assert files, "no evidence of a run was recorded"
    newest = files[-1]
    evidence = json.loads(newest.read_text(encoding="utf-8"))

    evaluation = _evaluate_expectations(evidence.get("results") or {})
    assert evaluation["all_passed"] is True, [
        c for c in evaluation["checks"] if c["status"] != "PASS"
    ]
