import json

from core.evm_oracle import (
    CANONICAL_HARNESS_ADDRESS,
    TOPIC_SECURITY_INVARIANT_BREACHED,
    TrustedEVMStateOracle,
    trusted_oracle,
)
from core.schemas import (
    AttackHypothesis,
    ExecutionEvidence,
    ExecutionResult,
    ExploitPayload,
    TargetProgram,
    VerificationResult,
)
from core.evaluator import evaluate_execution_trace
from core.evidence import HarnessVerdict
from core.schemas import ResultCategory


def _event_data(invariant_type: str, deficit: int) -> str:
    encoded = invariant_type.encode("utf-8")
    padded = encoded + b"\x00" * ((32 - len(encoded) % 32) % 32)
    return "0x" + (
        (64).to_bytes(32, "big")
        + deficit.to_bytes(32, "big")
        + len(encoded).to_bytes(32, "big")
        + padded
    ).hex()


def test_exact_target_registry_covers_antigravity_dataset_classes():
    expected = {
        "Vault", "ERC4626Vault", "AccessControlVault", "OracleLendingPool",
        "FlashLoanRewardPool", "SignatureReplayWallet", "AuctionDoS",
        "LendingLiquidation", "RewardDistributorLogic", "CrossContractBridge",
        "PrecisionStakingPool", "FeeShareYieldVault",
    }
    for target_name in expected:
        assert trusted_oracle.get_invariants_for_target(target_name), target_name


def test_unknown_target_has_no_substring_fallback():
    assert trusted_oracle.get_invariants_for_target("MyUnknownVaultClone") == []
    assert trusted_oracle.get_invariants_for_target("FeeShareYieldVault") != trusted_oracle.get_invariants_for_target("Vault")


def test_trusted_event_decodes_typed_invariant_and_deficit():
    oracle = TrustedEVMStateOracle()
    raw_logs = [{
        "address": CANONICAL_HARNESS_ADDRESS,
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _event_data("UNAUTHORIZED_ADMIN_DRAIN", 123),
    }]
    initial, final, context, genuine, spoofed = oracle.parse_harness_evidence(
        decoded_logs=[], stdout_text="", stderr_text="", raw_logs=raw_logs
    )
    assert genuine is True
    assert spoofed is False
    assert context["invariant_type"] == "UNAUTHORIZED_ADMIN_DRAIN"
    assert context["deficit"] == 123
    assert context["unauthorized_admin"] is True
    assert context["owner_hijacked"] is True


def test_untrusted_decoded_log_cannot_set_invariant_flags_or_deficit():
    oracle = TrustedEVMStateOracle()
    _, _, context, genuine, spoofed = oracle.parse_harness_evidence(
        decoded_logs=["[INVARIANT_BREACHED:UNAUTHORIZED_ADMIN_DRAIN] deficit: 999"],
        stdout_text="[INVARIANT_BREACHED:UNAUTHORIZED_ADMIN_DRAIN]",
        stderr_text="",
    )
    assert genuine is False
    assert spoofed is True
    assert "deficit" not in context
    assert "unauthorized_admin" not in context


def test_wrong_emitter_is_spoofed():
    oracle = TrustedEVMStateOracle()
    raw_logs = [{
        "address": "0x000000000000000000000000000000000000dead",
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _event_data("BUSINESS_LOGIC_FEE_DRAIN", 1),
    }]
    _, _, _, genuine, spoofed = oracle.parse_harness_evidence(
        decoded_logs=[], stdout_text="", stderr_text="", raw_logs=raw_logs
    )
    assert genuine is False
    assert spoofed is True


def test_success_without_trusted_event_is_not_a_safe_verdict():
    verdict = trusted_oracle.verify_execution(
        target=TargetProgram(name="Vault", source_code="contract Vault {}"),
        candidate_id="no-evidence",
        return_code=0,
        test_status="Success",
        decoded_logs=[],
        stdout_text="",
        stderr_text="",
        execution_time_sec=0.1,
    )
    assert verdict.invariant_breach is False
    assert verdict.confidence_status == "UNVERIFIED"
    assert "absence of evidence" in (verdict.failure_reason or "")


def test_trusted_erc4626_event_sets_share_inflation_flag():
    oracle = TrustedEVMStateOracle()
    raw_logs = [{
        "address": CANONICAL_HARNESS_ADDRESS,
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _event_data("SHARE_INFLATION_DEPOSITOR_DILUTION", 0),
    }]
    _, _, context, genuine, spoofed = oracle.parse_harness_evidence(
        decoded_logs=[], stdout_text="", stderr_text="", raw_logs=raw_logs
    )
    assert genuine is True
    assert spoofed is False
    assert context["share_inflation_detected"] is True
    assert context["deficit"] == 0


def test_oracle_shadow_result_is_persisted_but_does_not_override_trusted_reward():
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(
            vulnerability_type="Reentrancy",
            reasoning_trace="External call before balance update",
            attack_vector="Reenter withdrawAll",
        ),
        test_code="contract ExploitModule {}",
    )
    shadow = VerificationResult(
        execution_success=True,
        invariant_breach=False,
        confidence_status="UNVERIFIED",
        failure_reason="Raw event payload unavailable to secondary Oracle",
    )
    shadow_evidence = ExecutionEvidence(
        candidate_id=payload.candidate_id,
        target_id="Vault",
        execution_status="SUCCESS",
        execution_success=True,
        logs_reference=[],
    )
    raw = ExecutionResult(
        return_code=0,
        stdout="",
        stderr="",
        execution_time_sec=0.1,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        invariant_violated=True,
        test_status="Success",
        harness_verdict=HarnessVerdict.BREACH.value,
        harness_suite="test/VaultHarness.t.sol",
        evidence=shadow_evidence,
        verification_result=shadow,
    )
    verdict = evaluate_execution_trace(payload, raw)
    assert verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert verdict.reward_score == 0.5
    assert verdict.verification_result.confidence_status == "UNVERIFIED"
    assert verdict.evidence.candidate_id == payload.candidate_id
