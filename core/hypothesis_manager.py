"""
core/hypothesis_manager.py

Hypothesis Management Layer for Aegis-RLVR.
Bridges Auditor Findings to Exploit Generator:
1. Normalizes findings from LLM Auditor and Slither static analysis.
2. Deduplicates overlapping findings.
3. Classifies and prioritizes vulnerabilities into structured hypotheses.
4. Maintains candidate attempt history and feedback loop state transitions.
"""

from __future__ import annotations

import re
import uuid
from typing import List, Dict, Any, Optional, Tuple, Set

from core.schemas import (
    TargetProgram,
    VulnerabilityHypothesis,
    VerificationVerdict,
    ResultCategory,
    AttackHypothesis
)

# Standardized vulnerability classes (ordered by specificity)
VULNERABILITY_CLASSES = {
    "reentrancy-eth": "Reentrancy",
    "reentrancy-no-eth": "Reentrancy",
    "reentrancy": "Reentrancy",
    "rounding": "ERC4626Rounding",
    "firstdepositor": "ERC4626Inflation",
    "inflation": "ERC4626Inflation",
    "share": "ERC4626Inflation",
    "access": "AccessControl",
    "owner": "AccessControl",
    "auth": "AccessControl",
    "privilege": "AccessControl",
    "oracle": "OracleManipulation",
    "price": "OracleManipulation",
    "twap": "OracleManipulation",
    "flash": "FlashLoanAttack",
    "signature": "SignatureReplay",
    "replay": "SignatureReplay",
    "logic": "BusinessLogic",
    "cross": "CrossContract",
    "liquidation": "LiquidationLogic",
    "dos": "DenialOfService",
    "denial": "DenialOfService",
    "overflow": "ArithmeticPrecision",
    "underflow": "ArithmeticPrecision",
    "divide-before-multiply": "ArithmeticPrecision",
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 50,
    "LOW": 20,
    "INFORMATIONAL": 5,
}


def classify_vulnerability(text: str) -> str:
    """Classifies raw finding text into a standardized vulnerability category."""
    lower = text.lower()
    for keyword, standard_name in VULNERABILITY_CLASSES.items():
        if keyword in lower:
            return standard_name
    return "BusinessLogic"


def normalize_severity(sev_str: Optional[str]) -> str:
    """Normalizes severity strings to standard casing."""
    if not sev_str:
        return "Medium"
    s = str(sev_str).strip().upper()
    if "CRIT" in s:
        return "Critical"
    if "HIGH" in s:
        return "High"
    if "MED" in s:
        return "Medium"
    if "LOW" in s:
        return "Low"
    return "Medium"


class HypothesisManager:
    """
    Manages the lifecycle of vulnerability hypotheses.
    Transforms auditor findings into structured hypotheses, prioritizes them,
    and updates their validation status following execution and replay.
    """

    def __init__(self, target: TargetProgram):
        self.target = target
        self.hypotheses: Dict[str, VulnerabilityHypothesis] = {}
        self.execution_history: Dict[str, List[Dict[str, Any]]] = {}

    def ingest_auditor_findings(
        self,
        findings: List[Dict[str, Any]],
        source_label: str = "llm-auditor"
    ) -> List[VulnerabilityHypothesis]:
        """
        Normalizes raw findings from an auditor model into VulnerabilityHypothesis records.
        """
        normalized_list: List[VulnerabilityHypothesis] = []

        for idx, finding in enumerate(findings, 1):
            if not isinstance(finding, dict):
                continue

            raw_title = finding.get("title") or finding.get("name") or finding.get("check") or f"Finding-{idx}"
            raw_desc = finding.get("description") or finding.get("reasoning_trace") or ""
            raw_cat = finding.get("category") or raw_title
            raw_fn = finding.get("function") or finding.get("affected_function")
            raw_sev = finding.get("severity") or finding.get("impact") or "Medium"
            raw_vector = finding.get("attack_vector") or ""

            vuln_class = classify_vulnerability(f"{raw_title} {raw_cat} {raw_desc}")
            norm_sev = normalize_severity(raw_sev)

            # Extract attack preconditions and sequence if provided
            preconditions = []
            if "require" in raw_desc.lower():
                preconditions.append("Check prerequisites / function guards in target")
            if "deposit" in raw_desc.lower():
                preconditions.append("Requires attacker initial deposit or funding")

            sequence = []
            if raw_vector:
                steps = [s.strip() for s in re.split(r"\d+\.|\n-|\n", raw_vector) if s.strip()]
                sequence.extend(steps[:5])
            else:
                sequence.append(f"Invoke vulnerable function {raw_fn or 'target'}")
                sequence.append("Breach target state invariant")

            # Determine expected security invariant
            expected_inv = ""
            if self.target.invariants:
                expected_inv = self.target.invariants[0]
            else:
                expected_inv = f"{self.target.name} State Integrity"

            hyp_id = f"hyp_{self.target.name}_{vuln_class[:6].lower()}_{idx}"

            hypothesis = VulnerabilityHypothesis(
                hypothesis_id=hyp_id,
                target_id=self.target.name,
                source_finding_id=f"{source_label}_{idx}",
                vulnerability_class=vuln_class,
                affected_contract=self.target.name,
                affected_function=raw_fn,
                attack_preconditions=preconditions,
                attack_sequence=sequence,
                expected_invariant=expected_inv,
                severity=norm_sev,
                confidence=0.85 if norm_sev in ("Critical", "High") else 0.70,
                validation_status="normalized",
                evidence={"raw_finding": finding}
            )
            normalized_list.append(hypothesis)

        # Deduplicate and rank
        deduped = self.deduplicate_and_rank(normalized_list)
        for h in deduped:
            self.hypotheses[h.hypothesis_id] = h
            if h.hypothesis_id not in self.execution_history:
                self.execution_history[h.hypothesis_id] = []

        return deduped

    def ingest_slither_findings(self) -> List[VulnerabilityHypothesis]:
        """Ingests and normalizes static analysis findings from Slither."""
        if not self.target.slither_findings:
            return []
        return self.ingest_auditor_findings(self.target.slither_findings, source_label="slither")

    def deduplicate_and_rank(
        self,
        hypotheses: List[VulnerabilityHypothesis]
    ) -> List[VulnerabilityHypothesis]:
        """
        Deduplicates hypotheses with matching (vulnerability_class, affected_contract, affected_function)
        and ranks them by severity weight and confidence.
        """
        grouped: Dict[Tuple[str, str, Optional[str]], List[VulnerabilityHypothesis]] = {}
        for h in hypotheses:
            key = (h.vulnerability_class, h.affected_contract, h.affected_function)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(h)

        deduplicated: List[VulnerabilityHypothesis] = []

        for key, group in grouped.items():
            # Pick the highest confidence item as representative
            group.sort(key=lambda x: (SEVERITY_WEIGHTS.get(x.severity.upper(), 50), x.confidence), reverse=True)
            representative = group[0]

            # Merge preconditions and attack sequences from peers
            merged_preconds = set(representative.attack_preconditions)
            merged_seq = list(representative.attack_sequence)
            for other in group[1:]:
                merged_preconds.update(other.attack_preconditions)
                for step in other.attack_sequence:
                    if step not in merged_seq:
                        merged_seq.append(step)

            representative.attack_preconditions = list(merged_preconds)
            representative.attack_sequence = merged_seq[:6]
            representative.validation_status = "prioritized"
            deduplicated.append(representative)

        # Final ranking: sort by severity descending, confidence descending
        deduplicated.sort(
            key=lambda h: (
                SEVERITY_WEIGHTS.get(h.severity.upper(), 50),
                h.confidence,
                len(h.attack_sequence)
            ),
            reverse=True
        )

        return deduplicated

    def get_top_hypotheses(self, limit: int = 3) -> List[VulnerabilityHypothesis]:
        """Returns top prioritized hypotheses for candidate generation."""
        active = [h for h in self.hypotheses.values() if h.validation_status not in ("rejected",)]
        active.sort(
            key=lambda h: (
                SEVERITY_WEIGHTS.get(h.severity.upper(), 50),
                h.confidence,
                -h.attempt_count
            ),
            reverse=True
        )
        return active[:limit]

    def update_hypothesis_outcome(
        self,
        hypothesis_id: str,
        verdict: VerificationVerdict,
        candidate_id: str
    ) -> None:
        """
        Feedback Loop: Updates hypothesis state based on EVM execution and replay outcome.
        Status transitions:
        - proposed / prioritized -> generated
        - executed -> tested
        - verified & reproduced -> confirmed
        - repeated failures -> rejected
        """
        if hypothesis_id not in self.hypotheses:
            return

        hyp = self.hypotheses[hypothesis_id]
        hyp.attempt_count += 1

        record = {
            "candidate_id": candidate_id,
            "category": verdict.category.value,
            "reward": verdict.reward_score,
            "is_verified": verdict.is_verified,
            "reproduced": verdict.reproducible,
            "feedback": verdict.feedback[:200]
        }
        self.execution_history[hypothesis_id].append(record)

        if verdict.category == ResultCategory.EXPLOIT_CONFIRMED and verdict.is_verified and verdict.reproducible:
            # Genuine breach independently confirmed!
            hyp.validation_status = "confirmed"
            hyp.evidence = {
                "confirmed_candidate_id": candidate_id,
                "reward": verdict.reward_score,
                "feedback": verdict.feedback
            }
        elif verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED:
            # Provisional breach, waiting for replay confirmation
            hyp.validation_status = "tested"
        elif verdict.category == ResultCategory.CHEATCODE_DETECTED:
            # Failed due to forbidden cheatcodes
            hyp.last_error = "CHEATCODE_DETECTED: Candidate attempted sandbox escape"
            if hyp.validation_status != "confirmed":
                hyp.validation_status = "tested"
        elif verdict.category in (ResultCategory.COMPILATION_ERROR, ResultCategory.RUNTIME_REVERT):
            hyp.last_error = verdict.feedback[:250]
            if hyp.attempt_count >= 3 and hyp.validation_status != "confirmed":
                hyp.validation_status = "rejected"
            elif hyp.validation_status != "confirmed":
                hyp.validation_status = "tested"
        else:
            if hyp.attempt_count >= 3 and hyp.validation_status != "confirmed":
                hyp.validation_status = "rejected"
            elif hyp.validation_status != "confirmed":
                hyp.validation_status = "tested"

    def to_attack_hypothesis(self, hyp: VulnerabilityHypothesis) -> AttackHypothesis:
        """Converts VulnerabilityHypothesis to backwards-compatible AttackHypothesis."""
        seq_str = " -> ".join(hyp.attack_sequence) if hyp.attack_sequence else "Standard exploit sequence"
        return AttackHypothesis(
            vulnerability_type=hyp.vulnerability_class,
            reasoning_trace=f"Target: {hyp.affected_contract}, Function: {hyp.affected_function or 'General'}. Preconditions: {hyp.attack_preconditions}",
            attack_vector=seq_str,
            affected_functions=[hyp.affected_function] if hyp.affected_function else [],
            confidence_score=hyp.confidence
        )

    def get_hypothesis_failures(self, hypothesis_id: str) -> List[Dict[str, Any]]:
        """Returns history of failed attempts for a specific hypothesis."""
        return self.execution_history.get(hypothesis_id, [])
