"""
tests/test_hypothesis_pipeline.py

Test Suite for Stage 2: Hypothesis Pipeline, Auditor Integration, and Feedback Loop.
Tests:
1. Normalization of auditor findings into VulnerabilityHypothesis.
2. Deduplication and ranking of hypotheses.
3. Prompt formulation with hypothesis and failure feedback context.
4. Feedback loop state transitions (normalized -> prioritized -> tested -> confirmed / rejected).
"""

import pytest
from core.schemas import (
    TargetProgram,
    VulnerabilityHypothesis,
    VerificationVerdict,
    ResultCategory,
)
from core.hypothesis_manager import (
    HypothesisManager,
    classify_vulnerability,
    normalize_severity,
)
from core.llm_generator import build_analysis_prompt, build_refinement_prompt


def test_classify_vulnerability_categories():
    """Verifies that diverse finding descriptions map to canonical vulnerability classes."""
    assert classify_vulnerability("Possible reentrancy via low-level call") == "Reentrancy"
    assert classify_vulnerability("First depositor share inflation attack in vault") == "ERC4626Inflation"
    assert classify_vulnerability("Rounding down in convertToShares allows theft") == "ERC4626Rounding"
    assert classify_vulnerability("Missing onlyOwner on withdraw function") == "AccessControl"
    assert classify_vulnerability("Spot price manipulation via Uniswap reserves") == "OracleManipulation"
    assert classify_vulnerability("Arbitrary flash loan pump") == "FlashLoanAttack"
    assert classify_vulnerability("EIP-712 signature replay across chains") == "SignatureReplay"


def test_normalize_severity():
    """Verifies severity normalization to Title Case."""
    assert normalize_severity("CRITICAL") == "Critical"
    assert normalize_severity("high") == "High"
    assert normalize_severity("MEDIUM") == "Medium"
    assert normalize_severity("low") == "Low"
    assert normalize_severity(None) == "Medium"


def test_ingest_auditor_findings_normalization():
    """Verifies raw auditor findings normalization into VulnerabilityHypothesis."""
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { function withdraw() external {} }",
        invariants=["Depositor Solvency"]
    )
    mgr = HypothesisManager(target)

    raw_findings = [
        {
            "title": "Reentrancy in withdraw",
            "category": "Reentrancy",
            "severity": "Critical",
            "function": "withdraw",
            "description": "External call before balance reset allows reentrancy.",
            "attack_vector": "1. Deposit 1 ETH\n2. Call withdrawAll\n3. Reenter via fallback"
        },
        {
            "title": "Access control missing",
            "category": "AccessControl",
            "severity": "High",
            "function": "setAdmin",
            "description": "Public method modifies state without authorization.",
            "attack_vector": "Call setAdmin directly with attacker address"
        }
    ]

    hypotheses = mgr.ingest_auditor_findings(raw_findings, source_label="qwen-audit")
    assert len(hypotheses) == 2

    h1 = hypotheses[0]
    assert h1.vulnerability_class == "Reentrancy"
    assert h1.severity == "Critical"
    assert h1.affected_function == "withdraw"
    assert len(h1.attack_sequence) >= 2
    assert h1.validation_status == "prioritized"


def test_deduplicate_and_rank_hypotheses():
    """Verifies that duplicate findings are merged into one representative with combined vectors."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    mgr = HypothesisManager(target)

    duplicate_findings = [
        {
            "title": "Reentrancy flaw A",
            "category": "Reentrancy",
            "severity": "Critical",
            "function": "withdraw",
            "description": "Call before state update",
            "attack_vector": "1. Deposit\n2. Call withdraw"
        },
        {
            "title": "Reentrancy flaw B",
            "category": "Reentrancy",
            "severity": "High",
            "function": "withdraw",
            "description": "Duplicate detector on withdraw",
            "attack_vector": "3. Reenter via receive()"
        },
        {
            "title": "Minor formatting issue",
            "category": "Logic",
            "severity": "Low",
            "function": "help",
            "description": "Low severity logic note"
        }
    ]

    hypotheses = mgr.ingest_auditor_findings(duplicate_findings)
    # The two reentrancy findings on Vault.withdraw must be deduplicated into one!
    assert len(hypotheses) == 2

    reentrancy_hyp = [h for h in hypotheses if h.vulnerability_class == "Reentrancy"][0]
    assert reentrancy_hyp.severity == "Critical"
    # Attack sequence should combine steps from both
    assert any("Deposit" in s for s in reentrancy_hyp.attack_sequence)
    assert any("receive" in s for s in reentrancy_hyp.attack_sequence)

    # Ranking: Critical comes before Low
    assert hypotheses[0].severity == "Critical"
    assert hypotheses[1].severity == "Low"


def test_prompt_includes_hypothesis_and_failures():
    """Prompt must include structured hypothesis and previous failure traces."""
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault {}",
        invariants=["Depositor Solvency Coverage"]
    )
    hyp = VulnerabilityHypothesis(
        hypothesis_id="hyp_1",
        target_id="Vault",
        vulnerability_class="Reentrancy",
        affected_contract="Vault",
        affected_function="withdrawAll",
        attack_preconditions=["Attacker deposit required"],
        attack_sequence=["Deposit 1 ETH", "Invoke withdrawAll()", "Reenter via receive()"],
        expected_invariant="Depositor Solvency Coverage",
        severity="Critical"
    )
    failures = [
        {
            "candidate_id": "c1",
            "category": "RUNTIME_REVERT",
            "feedback": "Execution reverted: transfer failed"
        }
    ]

    prompt = build_analysis_prompt(target, hypothesis=hyp, previous_failures=failures)
    assert "Auditor Finding Hypothesis (Reentrancy - Critical Severity)" in prompt
    assert "withdrawAll" in prompt
    assert "Deposit 1 ETH" in prompt
    assert "PREVIOUS FAILED CANDIDATES" in prompt
    assert "Execution reverted: transfer failed" in prompt


def test_feedback_loop_status_transitions():
    """
    Verifies state transitions of hypotheses based on execution and replay verdicts:
    - prioritized -> tested -> confirmed
    - 3 failures -> rejected
    """
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    mgr = HypothesisManager(target)

    findings = [{
        "title": "Vault Reentrancy",
        "category": "Reentrancy",
        "severity": "Critical",
        "function": "withdrawAll",
        "description": "Drainable vault"
    }]
    hyps = mgr.ingest_auditor_findings(findings)
    hyp = hyps[0]
    hid = hyp.hypothesis_id
    assert hyp.validation_status == "prioritized"
    assert hyp.attempt_count == 0

    # 1. First execution: unconfirmed breach (waiting for replay)
    v1 = VerificationVerdict(
        target_name="Vault",
        is_verified=False,
        reward_score=0.5,
        category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
        vulnerability_type="Reentrancy",
        poc_code="contract ExploitModule {}",
        feedback="Pre-replay breach achieved"
    )
    mgr.update_hypothesis_outcome(hid, v1, "cand_1")
    assert hyp.attempt_count == 1
    assert hyp.validation_status == "tested"

    # 2. Replay confirms the breach!
    v2 = VerificationVerdict(
        target_name="Vault",
        is_verified=True,
        reward_score=1.0,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        vulnerability_type="Reentrancy",
        poc_code="contract ExploitModule {}",
        feedback="Replay confirmed in clean EVM!",
        reproducible=True
    )
    mgr.update_hypothesis_outcome(hid, v2, "cand_1")
    assert hyp.attempt_count == 2
    assert hyp.validation_status == "confirmed"
    assert hyp.evidence["reward"] == 1.0


def test_feedback_loop_rejection_after_exhaustion():
    """Hypothesis repeatedly failing (>=3 times) without breach transitions to rejected."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    mgr = HypothesisManager(target)

    findings = [{
        "title": "False Positive Claim",
        "category": "AccessControl",
        "severity": "Low",
        "function": "balanceOf",
        "description": "Hallucinated issue"
    }]
    hyps = mgr.ingest_auditor_findings(findings)
    hyp = hyps[0]
    hid = hyp.hypothesis_id

    # 3 consecutive runtime reverts
    for i in range(3):
        v = VerificationVerdict(
            target_name="Vault",
            is_verified=False,
            reward_score=-0.25,
            category=ResultCategory.RUNTIME_REVERT,
            vulnerability_type="AccessControl",
            poc_code="",
            feedback="Reverted: caller not authorized"
        )
        mgr.update_hypothesis_outcome(hid, v, f"cand_{i}")

    assert hyp.attempt_count == 3
    assert hyp.validation_status == "rejected"


def test_feedback_loop_provenance_preservation():
    """
    Stage 5 Test: Full feedback loop:
    Auditor -> Hypothesis Manager -> Exploit Generator -> Verification -> Replay -> Hypothesis Manager.
    Verifies that final replay result updates hypothesis status and preserves complete provenance lineage.
    """
    from sandbox.runner import ReplayOutcome

    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { function withdrawAll() external {} }",
        invariants=["INV-VAULT-01-SOLVENCY"]
    )
    mgr = HypothesisManager(target)

    # 1. Auditor finds reentrancy
    findings = [{
        "title": "Reentrancy in withdrawAll",
        "category": "Reentrancy",
        "severity": "Critical",
        "function": "withdrawAll",
        "description": "State updated after call",
        "attack_vector": "1. Deposit 1 ETH\n2. Call withdrawAll()\n3. Drain in receive()"
    }]
    hyps = mgr.ingest_auditor_findings(findings, source_label="auditor_v1")
    assert len(hyps) == 1
    hyp = hyps[0]
    hid = hyp.hypothesis_id
    assert hyp.validation_status == "prioritized"

    # 2. Generator takes top hypothesis
    top_hyps = mgr.get_top_hypotheses(limit=1)
    assert len(top_hyps) == 1
    prompt = build_analysis_prompt(target, hypothesis=top_hyps[0])
    assert "withdrawAll" in prompt

    # 3. Initial execution: Provisional breach
    cand_id = "cand_reentrancy_001"
    v_provisional = VerificationVerdict(
        target_name="Vault",
        is_verified=False,
        reward_score=0.5,
        category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
        vulnerability_type="Reentrancy",
        poc_code="contract ExploitModule {}",
        feedback="Provisional breach recorded"
    )
    mgr.update_hypothesis_outcome(hid, v_provisional, cand_id)
    assert hyp.validation_status == "tested"
    assert hyp.evidence.get("provisional_candidate_id") == cand_id

    # 4. Independent Replay succeeds
    replay_outcome = ReplayOutcome(
        target_name="Vault",
        candidate_id=cand_id,
        is_confirmed=True,
        status="CONFIRMED",
        initial_breached_invariants=["INV-VAULT-01-SOLVENCY"],
        replay_breached_invariants=["INV-VAULT-01-SOLVENCY"],
        initial_state_hash="init_hash_abc",
        replay_state_hash="replay_hash_xyz"
    )
    v_replay = VerificationVerdict(
        target_name="Vault",
        is_verified=True,
        reward_score=1.0,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        vulnerability_type="Reentrancy",
        poc_code="contract ExploitModule {}",
        feedback="Replay confirmed 100% in clean EVM",
        reproducible=True
    )
    mgr.update_hypothesis_outcome(hid, v_replay, cand_id, replay_outcome=replay_outcome)

    # 5. Verify final status and provenance preservation
    assert hyp.validation_status == "confirmed"
    provenance = hyp.evidence.get("provenance")
    assert provenance is not None
    assert provenance["source_finding_id"] == "auditor_v1_1"
    assert provenance["hypothesis_id"] == hid
    assert provenance["candidate_id"] == cand_id
    assert provenance["replay_status"] == "CONFIRMED"
    assert provenance["initial_state_hash"] == "init_hash_abc"
    assert provenance["replay_state_hash"] == "replay_hash_xyz"
    assert provenance["initial_breached_invariants"] == ["INV-VAULT-01-SOLVENCY"]
    assert "auditor_v1_1 ->" in provenance["provenance_lineage"]
    assert "EXPLOIT_CONFIRMED" in provenance["provenance_lineage"]


def test_structured_hypothesis_and_previous_failures_reach_generation_prompt():
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { function withdraw() external {} }",
        invariants=["Depositor solvency"]
    )
    manager = HypothesisManager(target)
    findings = [{
        "title": "Reentrancy in withdraw",
        "category": "Reentrancy",
        "severity": "Critical",
        "function": "withdraw",
        "description": "External call before state update",
        "attack_vector": "1. Deposit funds\n2. Call withdraw\n3. Reenter",
    }]
    hypothesis = manager.ingest_auditor_findings(findings)[0]
    prompt = build_analysis_prompt(
        target,
        hypothesis=hypothesis,
        previous_failures=[{
            "candidate_id": "cand-previous",
            "category": "RUNTIME_REVERT",
            "feedback": "withdraw reverted because the attacker had no initial deposit",
        }],
    )
    assert "Reentrancy" in prompt
    assert "Critical Severity" in prompt
    assert "cand-previous" in prompt
    assert "attacker had no initial deposit" in prompt


def test_refinement_prompt_preserves_hypothesis_and_failed_history():
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    manager = HypothesisManager(target)
    hypothesis = manager.ingest_auditor_findings([{
        "title": "Unauthorized withdraw",
        "category": "AccessControl",
        "severity": "High",
        "function": "withdraw",
        "description": "Missing authorization",
        "attack_vector": "Call withdraw as an unprivileged account",
    }])[0]
    prompt = build_refinement_prompt(
        target,
        "contract ExploitModule {}",
        "Foundry revert",
        hypothesis=hypothesis,
        previous_failures=[{"candidate_id": "old", "category": "RUNTIME_REVERT", "feedback": "Not exploitable"}],
    )
    assert "AccessControl" in prompt
    assert "Call withdraw" in prompt
    assert "candidate_id" not in prompt  # the history is rendered as concise failure context
    assert "old [RUNTIME_REVERT]" in prompt
