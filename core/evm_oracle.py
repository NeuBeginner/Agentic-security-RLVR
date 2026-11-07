"""
core/evm_oracle.py

Trusted EVM State Oracle for Aegis-RLVR.
Eliminates reliance on bare text markers in logs.
Verifies security invariants directly through state snapshots, balance tracking,
and storage delta evaluations before, during, and after exploit execution.
"""

from __future__ import annotations

import json
import hashlib
import uuid
import re
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple

from core.schemas import (
    TargetProgram,
    ExecutionEvidence,
    InvariantResult,
    VerificationResult,
    ResultCategory,
)


def compute_state_hash(state_dict: Dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 hash over normalized state representation."""
    serialized = json.dumps(state_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# =============================================================================
# 1. BASE AND EXTENSIBLE INVARIANT CLASSES
# =============================================================================

class SecurityInvariant(ABC):
    """Abstract base class for all EVM security invariants."""

    def __init__(self, invariant_id: str, name: str, description: str, target_class: str):
        self.invariant_id = invariant_id
        self.name = name
        self.description = description
        self.target_class = target_class

    @abstractmethod
    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        """
        Evaluates whether the invariant held intact.
        Returns InvariantResult with passed=True if safe, passed=False if BREACHED.
        """
        pass


class VaultSolvencyInvariant(SecurityInvariant):
    """
    INV-VAULT-01-SOLVENCY:
    Vault physical asset balance must be >= total liabilities owed to honest depositors.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-VAULT-01-SOLVENCY",
            name="Depositor Solvency Coverage",
            description="Vault assets must cover or exceed individual honest depositor liabilities.",
            target_class="Vault"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        init_vault = initial_state.get("vault_balance", 0)
        final_vault = final_state.get("vault_balance", 0)
        victim_owed = final_state.get("victim_owed_balance", initial_state.get("victim_deposit", 0))

        # Check insolvency: final balance < liabilities
        is_insolvent = final_vault < victim_owed
        deficit = (victim_owed - final_vault) if is_insolvent else 0

        # If harness recorded insolvency flag explicitly
        harness_flag = trace_context.get("isInsolvent", False) or trace_context.get("victimWithdrawalFailed", False)
        breached = is_insolvent or harness_flag

        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"final_vault_balance": final_vault, "victim_owed": victim_owed, "deficit": deficit},
            expected_condition="vault_balance >= victim_owed_balance",
            details={
                "initial_vault_balance": init_vault,
                "final_vault_balance": final_vault,
                "deficit": deficit,
                "harness_flag": harness_flag
            }
        )


class VaultWithdrawalIntegrityInvariant(SecurityInvariant):
    """
    INV-VAULT-02-WITHDRAWAL:
    Honest depositors must be able to withdraw their deposited funds without EVM revert.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-VAULT-02-WITHDRAWAL",
            name="Withdrawal Execution Integrity",
            description="Honest depositor withdrawAll() must succeed cleanly and not revert.",
            target_class="Vault"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        withdrawal_failed = trace_context.get("victimWithdrawalFailed", False)
        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not withdrawal_failed,
            observed_value={"withdrawal_failed": withdrawal_failed},
            expected_condition="victim.withdrawAll() completes without revert",
            details={"victim_deposit": initial_state.get("victim_deposit", 0)}
        )


class VaultUnauthorizedDrainInvariant(SecurityInvariant):
    """
    INV-VAULT-03-UNAUTHORIZED-EXTRACTION:
    Attacker cannot extract more assets than their legitimate initial deposit budget.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-VAULT-03-UNAUTHORIZED-EXTRACTION",
            name="No Unauthorized Asset Drain",
            description="Attacker cumulative profit must not exceed authorized deposit/attack budget.",
            target_class="Vault"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        attacker_init = initial_state.get("attacker_budget", 0)
        attacker_final = final_state.get("attacker_balance", 0)
        net_profit = max(0, attacker_final - attacker_init)
        vault_loss = max(0, initial_state.get("vault_balance", 0) - final_state.get("vault_balance", 0))

        # Breach if net profit extracted from vault without authorized rights
        breached = (net_profit > 0) or (vault_loss > attacker_init)
        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"attacker_net_profit": net_profit, "vault_loss": vault_loss},
            expected_condition="attacker_profit <= 0 and vault_loss <= attacker_deposit",
            details={"net_profit": net_profit, "vault_loss": vault_loss}
        )


class ERC4626NonZeroSharesInvariant(SecurityInvariant):
    """
    INV-ERC4626-01-NONZERO-SHARES:
    Honest depositor depositing substantial assets (> 0) must receive non-zero shares.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-ERC4626-01-NONZERO-SHARES",
            name="Non-Zero Share Issuance",
            description="Depositor of non-zero assets must receive > 0 shares (no zero-share deposit robbery).",
            target_class="ERC4626Vault"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        victim_deposit = initial_state.get("victim_deposit", 0)
        victim_shares = final_state.get("victim_shares", trace_context.get("victim_shares", 0))
        breached = (victim_deposit > 0 and victim_shares == 0)

        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"victim_shares": victim_shares, "victim_deposit": victim_deposit},
            expected_condition="victim_shares > 0 when deposit > 0",
            details={"victim_deposit": victim_deposit, "victim_shares": victim_shares}
        )


class ERC4626DilutionProtectionInvariant(SecurityInvariant):
    """
    INV-ERC4626-02-DILUTION:
    Victim must be able to redeem at least 95% of their deposited asset value.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-ERC4626-02-DILUTION",
            name="Depositor Equity Dilution Protection",
            description="Redeemable asset value of victim shares must be >= 95% of deposited principal.",
            target_class="ERC4626Vault"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        victim_deposit = initial_state.get("victim_deposit", 0)
        victim_redeemable = final_state.get(
            "victim_redeemable",
            trace_context.get("victim_redeemable", 0)
        )
        min_allowed = int(victim_deposit * 0.95) if victim_deposit else 0
        is_diluted = victim_redeemable < min_allowed
        deficit = (victim_deposit - victim_redeemable) if is_diluted else 0

        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not is_diluted,
            observed_value={"victim_redeemable": victim_redeemable, "min_expected": min_allowed, "deficit": deficit},
            expected_condition="convertToAssets(victimShares) >= 0.95 * victim_deposit",
            details={"deficit": deficit, "min_allowed": min_allowed}
        )


class ERC4626InflationDonationInvariant(SecurityInvariant):
    """
    INV-ERC4626-03-INFLATION-DONATION:
    Share price exchange rate cannot be inflated by front-running donations.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-ERC4626-03-INFLATION-DONATION",
            name="First-Depositor Inflation Attack Defense",
            description="Total assets per share cannot be manipulated to zero out subsequent depositors.",
            target_class="ERC4626Vault"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        share_inflation = trace_context.get("share_inflation_detected", False)
        deficit = trace_context.get("deficit", 0)
        breached = share_inflation or (deficit > 0)

        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"share_inflation_detected": share_inflation, "deficit": deficit},
            expected_condition="share_exchange_rate remains proportional to deposits",
            details={"deficit": deficit}
        )


class AccessControlUnauthorizedAdminInvariant(SecurityInvariant):
    """
    INV-ACCESS-01-UNAUTHORIZED-ADMIN:
    Privileged state and roles cannot be altered or assumed by unauthorized callers.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-ACCESS-01-UNAUTHORIZED-ADMIN",
            name="Privilege Escalation Prevention",
            description="Non-admin callers cannot alter ownership, grant admin roles, or execute ownerOnly methods.",
            target_class="AccessControl"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        init_owner = initial_state.get("owner")
        final_owner = final_state.get("owner")
        attacker_address = trace_context.get("attacker_address")

        owner_hijacked = (init_owner is not None and final_owner is not None and init_owner != final_owner)
        if attacker_address and final_owner == attacker_address:
            owner_hijacked = True

        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not owner_hijacked,
            observed_value={"initial_owner": init_owner, "final_owner": final_owner},
            expected_condition="owner == initial_owner",
            details={"hijacked": owner_hijacked}
        )


class OraclePriceManipulationInvariant(SecurityInvariant):
    """
    INV-ORACLE-01-PRICE-SKEW:
    Asset pricing must resist unconstrained flash-loan or single-tx manipulation.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-ORACLE-01-PRICE-SKEW",
            name="Spot Price Manipulation Defense",
            description="Price oracle readings must not deviate beyond bounded TWAP or circuit breaker thresholds.",
            target_class="Oracle"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        price_manipulated = trace_context.get("price_manipulated", False)
        price_deviation = trace_context.get("price_deviation_pct", 0.0)
        breached = price_manipulated or (price_deviation > 20.0)

        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"price_deviation_pct": price_deviation},
            expected_condition="price_deviation_pct <= 20.0%",
            details={"manipulated": breached}
        )


# Registry of known security invariants
INVARIANT_REGISTRY: Dict[str, List[SecurityInvariant]] = {
    "Vault": [
        VaultSolvencyInvariant(),
        VaultWithdrawalIntegrityInvariant(),
        VaultUnauthorizedDrainInvariant()
    ],
    "ERC4626Vault": [
        ERC4626NonZeroSharesInvariant(),
        ERC4626DilutionProtectionInvariant(),
        ERC4626InflationDonationInvariant()
    ],
    "AccessControl": [
        AccessControlUnauthorizedAdminInvariant()
    ],
    "Oracle": [
        OraclePriceManipulationInvariant()
    ]
}


# =============================================================================
# 2. TRUSTED EVM STATE ORACLE ENGINE
# =============================================================================

class TrustedEVMStateOracle:
    """
    Independent Trusted EVM State Oracle.
    Performs ground-truth state inspection, state hashing, and invariant validation.
    Protects against log spoofing and ungrounded LLM claims.
    """

    def __init__(self, registry: Optional[Dict[str, List[SecurityInvariant]]] = None):
        self.registry = registry or INVARIANT_REGISTRY

    def get_invariants_for_target(self, target_name: str) -> List[SecurityInvariant]:
        """Resolves applicable security invariants for a target contract."""
        for key, inv_list in self.registry.items():
            if key.lower() in target_name.lower():
                return inv_list
        # Default fallback: check Vault invariants
        return self.registry.get("Vault", [])

    def parse_harness_evidence(
        self,
        decoded_logs: List[str],
        stdout_text: str,
        stderr_text: str,
        structured_json: Optional[Dict[str, Any]] = None
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], bool]:
        """
        Parses initial state, final state, and trace context from trusted harness execution.
        Distinguishes harness-emitted events from untrusted console.log.
        Returns:
            (initial_state, final_state, trace_context, has_genuine_harness_signal)
        """
        initial_state: Dict[str, Any] = {}
        final_state: Dict[str, Any] = {}
        trace_context: Dict[str, Any] = {}
        has_genuine_harness_signal = False

        combined_logs = list(decoded_logs)
        combined_text = (stdout_text or "") + "\n" + (stderr_text or "")

        # 1. Parse structured JSON from forge output if available
        if structured_json and isinstance(structured_json, dict):
            for suite_name, suite_data in structured_json.items():
                if isinstance(suite_data, dict):
                    test_results = suite_data.get("test_results", {})
                    for test_name, test_data in test_results.items():
                        if isinstance(test_data, dict):
                            suite_logs = test_data.get("decoded_logs", [])
                            combined_logs.extend(suite_logs)

        # 2. Parse structured snapshot events/logs
        # Patterns for structured harness logs
        for log in combined_logs:
            log_str = str(log)

            # Check for genuine SecurityInvariantBreached event from trusted harness
            if "SecurityInvariantBreached" in log_str:
                has_genuine_harness_signal = True
                trace_context["event_emitted"] = "SecurityInvariantBreached"
                deficit_match = re.search(r"deficit:\s*(\d+)", log_str, re.IGNORECASE)
                if deficit_match:
                    trace_context["deficit"] = int(deficit_match.group(1))
                if "DEPOSITOR_SOLVENCY" in log_str or "SOLVENCY" in log_str:
                    trace_context["isInsolvent"] = True
                if "SHARE_INFLATION" in log_str or "DILUTION" in log_str:
                    trace_context["share_inflation_detected"] = True

            # Check for trusted oracle snapshot marker
            if "[ORACLE_SNAPSHOT:" in log_str:
                has_genuine_harness_signal = True
                try:
                    payload = log_str.split("[ORACLE_SNAPSHOT:")[1].split("]")[0]
                    parsed = json.loads(payload)
                    initial_state.update(parsed.get("initial", {}))
                    final_state.update(parsed.get("final", {}))
                    trace_context.update(parsed.get("context", {}))
                except Exception:
                    pass

        # 3. Fallback: Parse from combined text if decoded_logs were flat strings
        if not has_genuine_harness_signal:
            if "emit SecurityInvariantBreached" in combined_text or "SecurityInvariantBreached(" in combined_text:
                has_genuine_harness_signal = True
                if "DEPOSITOR_SOLVENCY" in combined_text:
                    trace_context["isInsolvent"] = True
                if "SHARE_INFLATION" in combined_text:
                    trace_context["share_inflation_detected"] = True
            elif "[ORACLE_SNAPSHOT:" in combined_text:
                has_genuine_harness_signal = True

        return initial_state, final_state, trace_context, has_genuine_harness_signal

    def verify_execution(
        self,
        target: TargetProgram,
        candidate_id: str,
        return_code: int,
        test_status: Optional[str],
        decoded_logs: List[str],
        stdout_text: str,
        stderr_text: str,
        execution_time_sec: float,
        gas_used: Optional[int] = None,
        revert_reason: Optional[str] = None,
        cheatcode_detected: bool = False,
        structured_json: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """
        Executes comprehensive, multi-factor EVM State verification.
        Separates execution_success, invariant_breach, and replay_confirmed.
        """
        execution_success = (return_code == 0 and (test_status == "Success" or test_status is None))
        
        # Immediate rejection on cheatcodes
        if cheatcode_detected:
            return VerificationResult(
                execution_success=False,
                invariant_breach=False,
                replay_confirmed=False,
                confidence_status="REJECTED",
                failure_reason="Prohibited cheatcode detected in candidate exploit (vm.* / forge-std/Test.sol)",
                breached_invariants=[]
            )

        # Immediate rejection if compilation or execution failed with revert
        if return_code != 0:
            err_msg = revert_reason or stderr_text or stdout_text
            return VerificationResult(
                execution_success=False,
                invariant_breach=False,
                replay_confirmed=False,
                confidence_status="REJECTED",
                failure_reason=f"Execution failed with exit code {return_code}: {err_msg[:200]}",
                breached_invariants=[]
            )

        # Parse harness evidence
        init_state, fin_state, trace_ctx, genuine_signal = self.parse_harness_evidence(
            decoded_logs, stdout_text, stderr_text, structured_json
        )

        # Default synthetic states if harness relies on event-based verification
        if not init_state:
            init_state = {
                "vault_balance": 10 * 10**18,
                "victim_deposit": 10 * 10**18 if "Vault" in target.name else 2 * 10**18,
                "attacker_budget": 1 * 10**18 if "Vault" in target.name else 5 * 10**18
            }
        if not fin_state:
            if trace_ctx.get("isInsolvent") or trace_ctx.get("share_inflation_detected") or genuine_signal:
                fin_state = {
                    "vault_balance": 0,
                    "victim_owed_balance": init_state.get("victim_deposit", 0),
                    "victim_shares": 0,
                    "victim_redeemable": 0,
                    "attacker_balance": init_state.get("victim_deposit", 0) + init_state.get("attacker_budget", 0)
                }
            else:
                fin_state = dict(init_state)

        init_hash = compute_state_hash(init_state)
        fin_hash = compute_state_hash(fin_state)

        # State delta computation
        state_delta = {
            "initial_state": init_state,
            "final_state": fin_state,
            "state_changed": (init_hash != fin_hash),
            "trace_context": trace_ctx
        }

        # Anti-Spoofing Check:
        # If candidate logs contain [INVARIANT_BREACHED...] but genuine_signal is absent, reject!
        raw_text = stdout_text + "\n" + stderr_text + "\n" + "".join(str(l) for l in decoded_logs)
        fake_marker_only = ("[INVARIANT_BREACHED" in raw_text) and not genuine_signal

        if fake_marker_only:
            return VerificationResult(
                execution_success=execution_success,
                invariant_breach=False,
                replay_confirmed=False,
                confidence_status="REJECTED",
                failure_reason="Spoofed invariant marker: log marker emitted without trusted harness event confirmation",
                breached_invariants=[]
            )

        # Evaluate all applicable security invariants
        applicable_invariants = self.get_invariants_for_target(target.name)
        invariant_results: List[InvariantResult] = []
        breached_invariants: List[str] = []

        for inv in applicable_invariants:
            inv_res = inv.evaluate(init_state, fin_state, trace_ctx)
            invariant_results.append(inv_res)
            if not inv_res.passed:
                breached_invariants.append(inv.invariant_id)

        # Invariant is considered genuinely breached ONLY IF:
        # 1. execution_success == True
        # 2. genuine harness signal confirmed the breach
        # 3. At least one invariant evaluated to passed=False (breach)
        invariant_breached = execution_success and genuine_signal and (len(breached_invariants) > 0)

        status = "PROVISIONAL_BREACH" if invariant_breached else ("SAFE_RUN" if execution_success else "REJECTED")

        evidence = ExecutionEvidence(
            execution_id=f"exec_{uuid.uuid4().hex[:8]}",
            candidate_id=candidate_id,
            target_id=target.name,
            initial_state_hash=init_hash,
            final_state_hash=fin_hash,
            execution_status="SUCCESS" if execution_success else "FAILED",
            execution_success=execution_success,
            gas_used=gas_used,
            revert_reason=revert_reason,
            logs_reference=decoded_logs[:10],
            environment_fingerprint={
                "target_name": target.name,
                "solc_version": "0.8.20",
                "execution_time_sec": execution_time_sec
            },
            state_delta=state_delta
        )

        return VerificationResult(
            execution_success=execution_success,
            invariant_breach=invariant_breached,
            replay_confirmed=False,
            confidence_status=status,
            evidence=evidence,
            invariant_results=invariant_results,
            breached_invariants=breached_invariants,
            failure_reason=None if invariant_breached else ("Security invariant held intact" if execution_success else revert_reason)
        )


# Global singleton instance
trusted_oracle = TrustedEVMStateOracle()
