"""
tests/test_runtime_oracle_and_harness_validation.py

Comprehensive Verification Suite for Agentic Security RLVR:
1. Runtime EVM State Oracle: raw logs, cryptographic topic matching, emitter verification, ABI decoding.
2. 100% Coverage of 12 Vulnerability Classes (positive breach, zero-deficit edge cases, negative safe runs).
3. 4 Synthetic Safe Controls (SecureVault, SecureAccessControlVault, SecureERC4626Vault, SecureOraclePool).
4. Anti-Spoofing and Fail-Closed Boundary Testing.
5. Trusted Execution Sandbox & Immutable Harness Protection.
6. Closed-Loop Agentic RLVR Pipeline & Provenance Lineage.
"""

import json
import pytest
from pathlib import Path

from core.evm_oracle import (
    CANONICAL_HARNESS_ADDRESS,
    CANONICAL_HARNESS_ADDRESSES,
    TOPIC_SECURITY_INVARIANT_BREACHED,
    TrustedEVMStateOracle,
    trusted_oracle,
    _decode_abi_string_and_uint,
    TARGET_INVARIANT_MAP,
    INVARIANT_REGISTRY,
)
from core.schemas import (
    TargetProgram,
    AttackHypothesis,
    VulnerabilityHypothesis,
    ExploitPayload,
    ExecutionResult,
    VerificationVerdict,
    ResultCategory,
)
from core.hypothesis_manager import HypothesisManager
from core.evaluator import evaluate_execution_trace
from core.evidence import HarnessVerdict
from core.llm_generator import (
    build_analysis_prompt,
    build_refinement_prompt,
    parse_model_response,
)
from sandbox.runner import (
    extract_trusted_harness_verdict,
    extract_trusted_harness_evidence,
    is_safe_target_name,
    load_trusted_harness_code,
    TRUSTED_HARNESS_CONTRACTS,
)


def _encode_event_data(invariant_type: str, deficit: int) -> str:
    """Encodes (string, uint256) into standard EVM ABI bytes."""
    encoded_str = invariant_type.encode("utf-8")
    padded_str = encoded_str + b"\x00" * ((32 - len(encoded_str) % 32) % 32)
    return "0x" + (
        (64).to_bytes(32, "big")
        + deficit.to_bytes(32, "big")
        + len(encoded_str).to_bytes(32, "big")
        + padded_str
    ).hex()


# =============================================================================
# 1. RUNTIME ORACLE: RAW EVM LOGS, EMITTER & TOPIC VERIFICATION
# =============================================================================

def test_oracle_verifies_topic_and_trusted_emitter():
    """Oracle accepts authentic event only when topic and emitter match trusted harness."""
    oracle = TrustedEVMStateOracle()
    harness_addr = list(CANONICAL_HARNESS_ADDRESSES)[0]

    raw_logs = [{
        "address": harness_addr,
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _encode_event_data("DEPOSITOR_SOLVENCY_COLLAPSE", 10 * 10**18),
    }]

    initial, final, context, genuine, spoofed = oracle.parse_harness_evidence(
        decoded_logs=[], stdout_text="", stderr_text="", raw_logs=raw_logs
    )
    assert genuine is True
    assert spoofed is False
    assert context["event_emitted"] == "SecurityInvariantBreached"
    assert context["invariant_type"] == "DEPOSITOR_SOLVENCY_COLLAPSE"
    assert context["deficit"] == 10 * 10**18
    assert context["isInsolvent"] is True


def test_oracle_rejects_untrusted_emitter_as_spoof():
    """Event emitted by attacker contract address must be flagged as spoof attempt."""
    oracle = TrustedEVMStateOracle()
    attacker_address = "0x000000000000000000000000000000000000bad1"

    raw_logs = [{
        "address": attacker_address,
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _encode_event_data("DEPOSITOR_SOLVENCY_COLLAPSE", 100),
    }]

    _, _, _, genuine, spoofed = oracle.parse_harness_evidence(
        decoded_logs=[], stdout_text="", stderr_text="", raw_logs=raw_logs
    )
    assert genuine is False
    assert spoofed is True


def test_oracle_rejects_wrong_topic_even_from_trusted_emitter():
    """Unknown or mismatched event topic cannot trigger invariant breach."""
    oracle = TrustedEVMStateOracle()
    harness_addr = list(CANONICAL_HARNESS_ADDRESSES)[0]
    wrong_topic = "0x0000000000000000000000000000000000000000000000000000000000000000"

    raw_logs = [{
        "address": harness_addr,
        "topics": [wrong_topic],
        "data": _encode_event_data("DEPOSITOR_SOLVENCY_COLLAPSE", 100),
    }]

    _, _, context, genuine, spoofed = oracle.parse_harness_evidence(
        decoded_logs=[], stdout_text="", stderr_text="", raw_logs=raw_logs
    )
    assert genuine is False
    assert "invariant_type" not in context


def test_console_logs_cannot_substitute_for_authentic_evm_logs():
    """Diagnostic text markers without authentic EVM log trigger anti-spoofing rejection."""
    oracle = TrustedEVMStateOracle()
    verdict = oracle.verify_execution(
        target=TargetProgram(name="Vault", source_code="contract Vault {}"),
        candidate_id="forged-marker",
        return_code=0,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        stdout_text="[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]",
        stderr_text="",
        execution_time_sec=0.1,
        raw_logs=[],
    )
    assert verdict.invariant_breach is False
    assert verdict.confidence_status == "REJECTED"
    assert "Spoofed invariant breach marker" in verdict.failure_reason


# =============================================================================
# 2. FULL 12 VULNERABILITY CLASSES COVERAGE (POSITIVE & ZERO-DEFICIT)
# =============================================================================

BENCHMARK_12_CLASSES = [
    ("Vault", "DEPOSITOR_SOLVENCY_COLLAPSE", 1000, "INV-VAULT-01-SOLVENCY"),
    ("ERC4626Vault", "SHARE_INFLATION_DEPOSITOR_DILUTION", 1000, "INV-ERC4626-01-NONZERO-SHARES"),
    ("AccessControlVault", "UNAUTHORIZED_ADMIN_DRAIN", 1000, "INV-ACCESS-01-UNAUTHORIZED-ADMIN"),
    ("OracleLendingPool", "ORACLE_PRICE_MANIPULATION", 1000, "INV-ORACLE-01-PRICE-SKEW"),
    ("FlashLoanRewardPool", "FLASH_LOAN_REWARD_DISTORTION", 1000, "INV-FLASH-01-REWARD-DRAIN"),
    ("SignatureReplayWallet", "SIGNATURE_REPLAY_DRAIN", 1000, "INV-SIG-01-REPLAY"),
    ("RewardDistributorLogic", "STATE_ACCOUNTING_INCONSISTENCY", 1000, "INV-REWARD-01-ACCOUNTING"),
    ("FeeShareYieldVault", "BUSINESS_LOGIC_FEE_DRAIN", 1000, "INV-FEE-01-UNAUTHORIZED-DRAIN"),
    ("LendingLiquidation", "LIQUIDATION_ACCOUNTING_DEFECT", 1000, "INV-LIQ-01-SOLVENCY"),
    ("CrossContractBridge", "CROSS_CONTRACT_DESYNCHRONIZATION", 1000, "INV-BRIDGE-01-CONSISTENCY"),
    ("AuctionDoS", "DENIAL_OF_SERVICE_LIVENESS", 1, "INV-DOS-01-AUCTION"),
    ("PrecisionStakingPool", "PRECISION_LOSS_FEE_BYPASS", 1, "INV-PRECISION-01-FEE"),
]


@pytest.mark.parametrize("target_name,event_type,deficit,expected_inv_id", BENCHMARK_12_CLASSES)
def test_all_12_classes_positive_breach_detection(target_name, event_type, deficit, expected_inv_id):
    """Every one of the 12 benchmark targets confirms breach when its harness event is emitted."""
    raw_logs = [{
        "address": CANONICAL_HARNESS_ADDRESS,
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _encode_event_data(event_type, deficit),
    }]
    target = TargetProgram(name=target_name, source_code=f"contract {target_name} {{}}")
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id=f"test-{target_name}",
        return_code=0,
        test_status="Success",
        decoded_logs=[],
        stdout_text="",
        stderr_text="",
        execution_time_sec=0.1,
        raw_logs=raw_logs,
    )
    assert res.execution_success is True
    assert res.invariant_breach is True
    assert res.confidence_status == "PROVISIONAL_BREACH"
    assert expected_inv_id in res.breached_invariants
    assert res.failure_reason is None


@pytest.mark.parametrize("target_name,event_type,_,expected_inv_id", BENCHMARK_12_CLASSES)
def test_all_12_classes_zero_deficit_edge_case(target_name, event_type, _, expected_inv_id):
    """A zero-deficit breach event must still trigger the invariant flag across all 12 classes."""
    raw_logs = [{
        "address": CANONICAL_HARNESS_ADDRESS,
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _encode_event_data(event_type, 0),
    }]
    target = TargetProgram(name=target_name, source_code=f"contract {target_name} {{}}")
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id=f"test-zero-{target_name}",
        return_code=0,
        test_status="Success",
        decoded_logs=[],
        stdout_text="",
        stderr_text="",
        execution_time_sec=0.1,
        raw_logs=raw_logs,
    )
    assert res.execution_success is True
    assert res.invariant_breach is True
    assert res.confidence_status == "PROVISIONAL_BREACH"
    assert expected_inv_id in res.breached_invariants


@pytest.mark.parametrize("target_name,_,__,___", BENCHMARK_12_CLASSES)
def test_all_12_classes_negative_no_breach(target_name, _, __, ___):
    """When execution succeeds cleanly without breach event, Oracle returns UNVERIFIED (never false SAFE)."""
    target = TargetProgram(name=target_name, source_code=f"contract {target_name} {{}}")
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id=f"test-neg-{target_name}",
        return_code=0,
        test_status="Success",
        decoded_logs=[],
        stdout_text="",
        stderr_text="",
        execution_time_sec=0.1,
        raw_logs=[],
    )
    assert res.execution_success is True
    assert res.invariant_breach is False
    assert res.confidence_status == "UNVERIFIED"
    assert res.breached_invariants == []
    assert "absence of evidence" in (res.failure_reason or "")


# =============================================================================
# 3. FOUR SYNTHETIC SAFE CONTROL CONTRACTS
# =============================================================================

SAFE_CONTROLS = [
    ("SecureVault", "Vault"),
    ("SecureAccessControlVault", "AccessControl"),
    ("SecureERC4626Vault", "ERC4626Vault"),
    ("SecureOraclePool", "Oracle"),
]


@pytest.mark.parametrize("ctrl_name,expected_family", SAFE_CONTROLS)
def test_safe_controls_resolve_to_proper_invariant_families(ctrl_name, expected_family):
    """Safe controls map to their respective invariant families without fallback."""
    invariants = trusted_oracle.get_invariants_for_target(ctrl_name)
    assert invariants, f"Control {ctrl_name} must have registered invariants"
    assert TARGET_INVARIANT_MAP.get(ctrl_name.lower()) == expected_family


@pytest.mark.parametrize("ctrl_name,_", SAFE_CONTROLS)
def test_safe_controls_reject_spoofed_markers(ctrl_name, _):
    """Attacking safe controls by injecting fake console markers fails anti-spoofing."""
    target = TargetProgram(name=ctrl_name, source_code=f"contract {ctrl_name} {{}}")
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id=f"spoof-{ctrl_name}",
        return_code=0,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        stdout_text="[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]",
        stderr_text="",
        execution_time_sec=0.1,
        raw_logs=[],
    )
    assert res.invariant_breach is False
    assert res.confidence_status == "REJECTED"
    assert "Spoofed invariant breach marker" in res.failure_reason


# =============================================================================
# 4. FAIL-CLOSED BOUNDARIES: UNKNOWN CONTRACTS & PATH TRAVERSAL
# =============================================================================

def test_unknown_target_fails_closed_without_vault_fallback():
    """An unknown target name receives no default/fallback invariants and is firmly rejected."""
    target = TargetProgram(name="UnknownCustomPool", source_code="contract UnknownCustomPool {}")
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id="unknown-test",
        return_code=0,
        test_status="Success",
        decoded_logs=[],
        stdout_text="",
        stderr_text="",
        execution_time_sec=0.1,
    )
    assert res.invariant_breach is False
    assert res.confidence_status == "REJECTED"
    assert "No applicable security invariants registered" in res.failure_reason


def test_production_trusted_harness_allowlist_boundaries():
    """Production trusted harness allowlist is strictly restricted to Vault and ERC4626Vault."""
    assert "Vault" in TRUSTED_HARNESS_CONTRACTS
    assert "ERC4626Vault" in TRUSTED_HARNESS_CONTRACTS
    assert len(TRUSTED_HARNESS_CONTRACTS) == 2, "Production allowlist boundary must remain bounded"


def test_path_traversal_in_target_name_rejected():
    """Path traversal sequences in target names are blocked before filesystem access."""
    assert not is_safe_target_name("../Vault")
    assert not is_safe_target_name("Vault/../../etc/passwd")
    with pytest.raises(ValueError, match="safe Solidity identifier"):
        load_trusted_harness_code("../Vault")


# =============================================================================
# 5. REAL FOUNDRY OUTPUT VERIFICATION & EXTRACT EVIDENCE
# =============================================================================

def test_extract_trusted_harness_evidence_from_structured_json():
    """extract_trusted_harness_evidence extracts verdict, harness address, and raw logs."""
    harness_addr = "0x7fa9385be102ac3eac297483dd6233d62b3e1496"
    mock_log = {
        "address": harness_addr,
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _encode_event_data("DEPOSITOR_SOLVENCY_COLLAPSE", 5000),
    }
    structured_data = {
        "test/VaultHarness.t.sol:VaultTrustedHarness": {
            "test_results": {
                "testExploit()": {
                    "status": "Success",
                    "reason": None,
                    "logs": [mock_log],
                    "traces": [
                        [
                            "Execution",
                            {"arena": [{"trace": {"address": harness_addr}}]}
                        ]
                    ],
                }
            }
        }
    }

    verdict, suite, status, reason, addr, logs = extract_trusted_harness_evidence(
        structured_data, "Vault"
    )
    assert verdict == HarnessVerdict.BREACH.value
    assert suite == "test/VaultHarness.t.sol"
    assert status == "Success"
    assert reason is None
    assert addr == harness_addr
    assert len(logs) == 1
    assert logs[0] == mock_log


def test_oracle_handles_real_foundry_output_fixture():
    """Verifies Oracle end-to-end against real Forge --offline --json -vvvv output."""
    real_forge_json_path = Path("C:/Users/Telekom/.gemini/antigravity/brain/910f0fcf-c321-428c-b37e-cc80f7993b1e/scratch/real_forge_out.json")
    if not real_forge_json_path.exists():
        pytest.skip("Scratch file real_forge_out.json not available in environment")

    with open(real_forge_json_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    s_idx = raw_text.find("{")
    e_idx = raw_text.rfind("}")
    structured_json = json.loads(raw_text[s_idx : e_idx + 1])

    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    res = trusted_oracle.verify_execution(
        target=target,
        candidate_id="real-modal-forge-execution",
        return_code=0,
        test_status="Success",
        decoded_logs=["[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]"],
        stdout_text=raw_text,
        stderr_text="",
        execution_time_sec=1.2,
        structured_json=structured_json,
    )

    assert res.execution_success is True
    assert res.invariant_breach is True
    assert res.confidence_status == "PROVISIONAL_BREACH"
    assert "INV-VAULT-01-SOLVENCY" in res.breached_invariants
    assert res.failure_reason is None


# =============================================================================
# 6. FULL AGENTIC RLVR PIPELINE & PROVENANCE LINEAGE
# =============================================================================

def test_full_agentic_closed_loop_lifecycle():
    """
    Validates complete pipeline sequence:
    Slither findings -> HypothesisManager -> Generator prompt -> ExploitPayload
    -> Oracle verification -> Evaluator verdict -> Replay feedback -> Provenance update.
    """
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { function withdrawAll() external {} }",
        slither_findings=[{
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "High",
            "description": "Possible reentrancy via low-level call{value} prior to state updates."
        }]
    )

    # 1. Ingest findings into HypothesisManager
    mgr = HypothesisManager(target)
    hypotheses = mgr.ingest_slither_findings()
    assert len(hypotheses) == 1
    hyp = hypotheses[0]
    assert hyp.vulnerability_class == "Reentrancy"
    assert hyp.validation_status == "prioritized"
    hyp_id = hyp.hypothesis_id

    # 2. Generator receives hypothesis context and failure history
    previous_failures = [{"candidate_id": "cand_001", "category": "RUNTIME_REVERT", "feedback": "Reverted in transfer"}]
    prompt = build_analysis_prompt(target, hypothesis=hyp, previous_failures=previous_failures)
    assert hyp_id not in prompt or "Reentrancy" in prompt
    assert "PREVIOUS FAILED CANDIDATES" in prompt
    assert "cand_001" in prompt

    # 3. ExploitPayload preserves hypothesis_id and candidate_id
    candidate_code = """```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Vault} from "../src/Vault.sol";

contract ExploitModule {
    Vault public targetContract;
    constructor(address _target) payable { targetContract = Vault(payable(_target)); }
    function runExploit() external payable {}
    receive() external payable {}
}
```"""
    payload = parse_model_response(
        target,
        candidate_code,
        attempt_idx=1,
        hypothesis=hyp,
        candidate_id="cand_real_002"
    )
    assert payload.candidate_id == "cand_real_002"
    assert payload.hypothesis_id == hyp_id
    assert payload.hypothesis.hypothesis_id == hyp_id
    assert payload.hypothesis.vulnerability_type == "Reentrancy"

    # 4. EVM Execution and Oracle verification
    harness_addr = list(CANONICAL_HARNESS_ADDRESSES)[0]
    raw_logs = [{
        "address": harness_addr,
        "topics": [TOPIC_SECURITY_INVARIANT_BREACHED],
        "data": _encode_event_data("DEPOSITOR_SOLVENCY_COLLAPSE", 10 * 10**18),
    }]
    oracle_res = trusted_oracle.verify_execution(
        target=target,
        candidate_id=payload.candidate_id,
        return_code=0,
        test_status="Success",
        decoded_logs=[],
        stdout_text="",
        stderr_text="",
        execution_time_sec=0.5,
        raw_logs=raw_logs,
        trusted_harness_address=harness_addr,
    )
    assert oracle_res.invariant_breach is True

    # 5. Evaluator verdict
    exec_result = ExecutionResult(
        return_code=0,
        stdout="",
        stderr="",
        execution_time_sec=0.5,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        invariant_violated=True,
        test_status="Success",
        harness_verdict=HarnessVerdict.BREACH.value,
        harness_suite="test/VaultHarness.t.sol",
        reproducibility_confirmed=True,
        verification_result=oracle_res,
        evidence=oracle_res.evidence,
        invariant_results=oracle_res.invariant_results,
    )
    verdict = evaluate_execution_trace(payload, exec_result)
    assert verdict.is_verified is True
    assert verdict.reproducible is True
    assert verdict.category == ResultCategory.EXPLOIT_CONFIRMED

    # 6. Feedback into HypothesisManager: updates status and full provenance lineage
    mgr.update_hypothesis_outcome(
        hypothesis_id=hyp_id,
        verdict=verdict,
        candidate_id=payload.candidate_id
    )
    assert hyp.validation_status == "confirmed"
    assert hyp.attempt_count == 1
    assert "provenance" in hyp.evidence
    prov = hyp.evidence["provenance"]
    assert prov["candidate_id"] == "cand_real_002"
    assert prov["is_verified"] is True
    assert prov["reproduced"] is True
    assert f"{hyp_id} -> cand_real_002" in prov["provenance_lineage"]
