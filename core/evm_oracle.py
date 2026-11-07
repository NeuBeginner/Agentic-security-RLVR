"""
core/evm_oracle.py

Trusted EVM State Oracle for Aegis-RLVR (Hardened).
Eliminates synthetic state fabrication and ungrounded heuristics.
Verifies security invariants strictly through:
1. Cryptographic event topic and trusted harness emitter address verification.
2. Anti-spoofing rejection of arbitrary logs, console.log text, and unconfirmed snapshots.
3. Actual EVM post-execution state without synthetic fallbacks.
4. Precedence of specialized invariants over generic invariants, with no fallback to Vault
   invariants for unknown contract targets.
"""

from __future__ import annotations

import json
import hashlib
import uuid
import re
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple, Set

from core.schemas import (
    TargetProgram,
    ExecutionEvidence,
    InvariantResult,
    VerificationResult,
    ResultCategory,
)


# =============================================================================
# 0. PURE PYTHON KECCAK-256 IMPLEMENTATION (NIST FIPS 202 TESTED)
# =============================================================================

def keccak256(data: bytes) -> str:
    """Computes standard Ethereum Keccak-256 hash (0x-prefixed hex string)."""
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]
    rate_bytes = 136  # (1600 - 512) / 8 for 256-bit output
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate_bytes != (rate_bytes - 1):
        padded.append(0x00)
    padded.append(0x80)

    state = [[0] * 5 for _ in range(5)]
    for b in range(0, len(padded), rate_bytes):
        block = padded[b : b + rate_bytes]
        for i in range(17):
            w = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
            state[i % 5][i // 5] ^= w

        for round_idx in range(24):
            # Theta
            C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) & 0xFFFFFFFFFFFFFFFF) | (C[(x + 1) % 5] >> 63)) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= D[x]

            # Rho and Pi
            B = [[0] * 5 for _ in range(5)]
            ROT = [
                [0, 36, 3, 41, 18],
                [1, 44, 10, 45, 2],
                [62, 6, 43, 15, 61],
                [28, 55, 25, 21, 56],
                [27, 20, 39, 8, 14]
            ]
            for x in range(5):
                for y in range(5):
                    r_shift = ROT[x][y]
                    val = state[x][y]
                    B[y][(2 * x + 3 * y) % 5] = (
                        (((val << r_shift) & 0xFFFFFFFFFFFFFFFF) | (val >> (64 - r_shift))) if r_shift else val
                    )

            # Chi
            for x in range(5):
                for y in range(5):
                    state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

            # Iota
            state[0][0] ^= RC[round_idx]

    out = bytearray()
    for i in range(4):
        out.extend(state[i % 5][i // 5].to_bytes(8, "little"))
    return "0x" + out[:32].hex()


# Canonical Event Topics & Default Test Runner Addresses in Foundry
CANONICAL_HARNESS_ADDRESS = "0xb4c79dab8f259c7aee6e5b2aa729821864227e84".lower()
CANONICAL_HARNESS_ADDRESSES = {
    CANONICAL_HARNESS_ADDRESS,
    "0x7fa9385be102ac3eac297483dd6233d62b3e1496".lower(),
}
FORGE_CONSOLE_ADDRESS = "0x000000000000000000636f6e736f6c652e6c6f67".lower()

# Topic for SecurityInvariantBreached(string,uint256)
TOPIC_SECURITY_INVARIANT_BREACHED = keccak256(b"SecurityInvariantBreached(string,uint256)").lower()
# Topic for OracleSnapshot(string,string,string) -> (initial, final, context)
TOPIC_ORACLE_SNAPSHOT = keccak256(b"OracleSnapshot(string,string,string)").lower()



def _decode_abi_string_and_uint(data_hex: str) -> Tuple[str, int]:
    """Decode (string,uint256) event data without trusting decoded log text."""
    try:
        raw = bytes.fromhex(str(data_hex or "").removeprefix("0x"))
        if len(raw) < 64:
            return "", 0
        string_offset = int.from_bytes(raw[0:32], "big")
        amount = int.from_bytes(raw[32:64], "big")
        if string_offset + 32 > len(raw):
            return "", amount
        length = int.from_bytes(raw[string_offset:string_offset + 32], "big")
        start = string_offset + 32
        end = start + length
        if end > len(raw):
            return "", amount
        return raw[start:end].decode("utf-8", errors="strict"), amount
    except (ValueError, UnicodeDecodeError, TypeError):
        return "", 0


def compute_state_hash(state_dict: Dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 hash over normalized state representation."""
    if not state_dict:
        return "empty_state"
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
        has_state = bool(initial_state or final_state)
        init_vault = initial_state.get("vault_balance", 0)
        final_vault = final_state.get("vault_balance", 0)
        victim_owed = final_state.get("victim_owed_balance", initial_state.get("victim_deposit", 0))

        # Check insolvency from actual state if state snapshot exists
        is_insolvent = (final_vault < victim_owed) if has_state else False
        deficit = (victim_owed - final_vault) if (has_state and is_insolvent) else 0

        # If verified harness recorded insolvency flag explicitly with genuine signal
        harness_flag = (
            trace_context.get("isInsolvent", False)
            or trace_context.get("victimWithdrawalFailed", False)
            or trace_context.get("depositor_solvency_collapse", False)
        )
        event_deficit = trace_context.get("deficit", 0)
        if event_deficit > 0:
            deficit = max(deficit, event_deficit)

        breached = is_insolvent or harness_flag or (event_deficit > 0)

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
                "harness_flag": harness_flag,
                "has_state": has_state
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
        harness_inflation = trace_context.get("share_inflation_detected", False)
        breached = (victim_deposit > 0 and victim_shares == 0) or harness_inflation

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
        if trace_context.get("deficit", 0) > 0:
            deficit = max(deficit, trace_context.get("deficit", 0))
            is_diluted = True

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
        if trace_context.get("owner_hijacked") or trace_context.get("unauthorized_admin"):
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


class FlashLoanArbitrageInvariant(SecurityInvariant):
    """
    INV-FLASH-01-REWARD-DRAIN:
    Flash-loan borrower cannot drain pool rewards within the same transaction.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-FLASH-01-REWARD-DRAIN",
            name="Flash Loan Reward Extraction Defense",
            description="Pool rewards cannot be extracted using flash-minted/borrowed balances without lockup.",
            target_class="FlashLoan"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        reward_drained = trace_context.get("reward_drained", False)
        deficit = trace_context.get("deficit", 0)
        breached = reward_drained or (deficit > 0)
        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"reward_drained": reward_drained, "deficit": deficit},
            expected_condition="pool_rewards remain intact",
            details={"deficit": deficit}
        )


class SignatureReplayInvariant(SecurityInvariant):
    """
    INV-SIG-01-REPLAY:
    Signatures must include nonces and cannot be executed more than once.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-SIG-01-REPLAY",
            name="Signature Nonce and Replay Defense",
            description="Signatures cannot be replayed across transactions to double-claim funds.",
            target_class="SignatureReplay"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        replay_detected = trace_context.get("replay_executed", False)
        deficit = trace_context.get("deficit", 0)
        breached = replay_detected or (deficit > 0)
        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"replay_detected": replay_detected, "deficit": deficit},
            expected_condition="each signature executed at most once",
            details={"deficit": deficit}
        )


class AuctionDoSInvariant(SecurityInvariant):
    """
    INV-DOS-01-AUCTION:
    Auction contract must not permanently lock refunds or stall bidding.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-DOS-01-AUCTION",
            name="Auction DoS Resistance",
            description="Highest bidder change must not revert due to failing recipient fallback.",
            target_class="Auction"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        dos_detected = trace_context.get("dos_detected", False)
        breached = dos_detected or (trace_context.get("deficit", 0) > 0)
        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"dos_detected": dos_detected},
            expected_condition="auction bids can always proceed",
            details={}
        )


class LiquidationSolvencyInvariant(SecurityInvariant):
    """
    INV-LIQ-01-SOLVENCY:
    Liquidations must accurately evaluate health factors without under-collateralized bad debt.
    """
    def __init__(self):
        super().__init__(
            invariant_id="INV-LIQ-01-SOLVENCY",
            name="Liquidation Health Factor Integrity",
            description="Protocol must liquidate positions strictly according to collateral health factors.",
            target_class="Liquidation"
        )

    def evaluate(
        self,
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        trace_context: Dict[str, Any]
    ) -> InvariantResult:
        bad_debt = trace_context.get("bad_debt_created", False)
        deficit = trace_context.get("deficit", 0)
        breached = bad_debt or (deficit > 0)
        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not breached,
            observed_value={"bad_debt": bad_debt, "deficit": deficit},
            expected_condition="no unbacked debt created",
            details={"deficit": deficit}
        )



class TypedHarnessEventInvariant(SecurityInvariant):
    """Invariant asserted by a typed event from the repository-owned harness."""
    def __init__(self, invariant_id: str, name: str, description: str, target_class: str, event_type: str):
        super().__init__(invariant_id, name, description, target_class)
        self.event_type = event_type

    def evaluate(self, initial_state: Dict[str, Any], final_state: Dict[str, Any], trace_context: Dict[str, Any]) -> InvariantResult:
        matched = bool(trace_context.get("verified_event")) and trace_context.get("invariant_type") == self.event_type
        return InvariantResult(
            invariant_id=self.invariant_id,
            invariant_name=self.name,
            passed=not matched,
            observed_value={"invariant_type": trace_context.get("invariant_type"), "deficit": trace_context.get("deficit", 0)},
            expected_condition=f"trusted harness did not emit {self.event_type}",
            details={"verified_event": bool(trace_context.get("verified_event")), "event_type": self.event_type}
        )


# Invariant Registry mapping
INVARIANT_REGISTRY: Dict[str, List[SecurityInvariant]] = {
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
    ],
    "FlashLoan": [
        FlashLoanArbitrageInvariant()
    ],
    "SignatureReplay": [
        SignatureReplayInvariant()
    ],
    "Auction": [
        AuctionDoSInvariant()
    ],
    "Liquidation": [
        LiquidationSolvencyInvariant()
    ],
    "Vault": [
        VaultSolvencyInvariant(),
        VaultWithdrawalIntegrityInvariant(),
        VaultUnauthorizedDrainInvariant()
    ],
    "RewardDistributorLogic": [
        TypedHarnessEventInvariant("INV-REWARD-01-ACCOUNTING", "Reward Accounting Integrity",
            "Reward distribution must not create an accounting deficit.", "RewardDistributorLogic",
            "STATE_ACCOUNTING_INCONSISTENCY")
    ],
    "CrossContractBridge": [
        TypedHarnessEventInvariant("INV-BRIDGE-01-CONSISTENCY", "Cross-Contract Bridge Consistency",
            "Bridge accounting and asset movement must remain synchronized.", "CrossContractBridge",
            "CROSS_CONTRACT_DESYNCHRONIZATION")
    ],
    "PrecisionStakingPool": [
        TypedHarnessEventInvariant("INV-PRECISION-01-FEE", "Staking Fee Precision Integrity",
            "Non-zero deposits must not bypass required fee accounting through rounding.", "PrecisionStakingPool",
            "PRECISION_LOSS_FEE_BYPASS")
    ],
    "FeeShareYieldVault": [
        TypedHarnessEventInvariant("INV-FEE-01-UNAUTHORIZED-DRAIN", "Fee Share Yield Protection",
            "Yield must not be drained by unauthorized fee withdrawal.", "FeeShareYieldVault",
            "BUSINESS_LOGIC_FEE_DRAIN")
    ]
}


# Exact dataset target names to invariant families. Unlisted names fail closed.
TARGET_INVARIANT_MAP: Dict[str, str] = {
    "vault": "Vault",
    "securevault": "Vault",
    "erc4626vault": "ERC4626Vault",
    "secureerc4626vault": "ERC4626Vault",
    "accesscontrolvault": "AccessControl",
    "secureaccesscontrolvault": "AccessControl",
    "oraclelendingpool": "Oracle",
    "secureoraclepool": "Oracle",
    "flashloanrewardpool": "FlashLoan",
    "signaturereplaywallet": "SignatureReplay",
    "auctiondos": "Auction",
    "lendingliquidation": "Liquidation",
    "rewarddistributorlogic": "RewardDistributorLogic",
    "crosscontractbridge": "CrossContractBridge",
    "precisionstakingpool": "PrecisionStakingPool",
    "feeshareyieldvault": "FeeShareYieldVault",
}


# Precedence hierarchy: specialized classes must be evaluated before generic classes
# "Vault" is placed strictly last so specialized vaults (e.g. ERC4626Vault, AccessControlVault)
# receive their dedicated invariants first.
REGISTRY_PRECEDENCE = [
    "ERC4626Vault",
    "AccessControl",
    "Oracle",
    "FlashLoan",
    "SignatureReplay",
    "Auction",
    "Liquidation",
    "RewardDistributorLogic",
    "CrossContractBridge",
    "PrecisionStakingPool",
    "FeeShareYieldVault",
    "Vault",
]


# =============================================================================
# 2. TRUSTED EVM STATE ORACLE ENGINE
# =============================================================================

class TrustedEVMStateOracle:
    """
    Independent Trusted EVM State Oracle (Hardened).
    Performs ground-truth state inspection, cryptographic topic validation,
    trusted harness emitter checks, and invariant evaluation.
    Guarantees:
    - Zero trust in model-supplied strings or console.log.
    - Zero synthetic state fabrication when real snapshots are absent.
    - Rejection of spoofed events and unconfirmed snapshots.
    - Strict precedence of specialized invariants over generic rules.
    - Refusal to apply Vault invariants to unknown target contracts.
    """

    def __init__(self, registry: Optional[Dict[str, List[SecurityInvariant]]] = None):
        self.registry = registry or INVARIANT_REGISTRY

    def get_invariants_for_target(self, target_name: str) -> List[SecurityInvariant]:
        """Resolve by exact target identity. Unknown targets receive no fallback rules."""
        normalized = str(target_name or "").strip().casefold()
        registry_key = TARGET_INVARIANT_MAP.get(normalized)
        if registry_key is None:
            # Allow an exact registry key for controlled/custom test registries only.
            registry_key = next((key for key in self.registry if key.casefold() == normalized), None)
        if registry_key is None:
            return []
        return list(self.registry.get(registry_key, []))

    def parse_harness_evidence(
        self,
        decoded_logs: List[str],
        stdout_text: str,
        stderr_text: str,
        structured_json: Optional[Dict[str, Any]] = None,
        raw_logs: Optional[List[Dict[str, Any]]] = None,
        trusted_harness_address: Optional[str] = None
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], bool, bool]:
        """
        Parses initial state, final state, and trace context from trusted harness execution.
        Distinguishes harness-emitted events from untrusted console.log and exploit events.
        
        Verification rules:
        - Must verify emitter address matches trusted harness.
        - Must verify event topic matches canonical keccak256 hash.
        - Rejects any spoofed markers in console.log or untrusted log streams.
        
        Returns:
            (initial_state, final_state, trace_context, has_genuine_harness_signal, spoof_attempt_detected)
        """
        initial_state: Dict[str, Any] = {}
        final_state: Dict[str, Any] = {}
        trace_context: Dict[str, Any] = {}
        has_genuine_harness_signal = False
        spoof_attempt_detected = False

        valid_emitters: Set[str] = set(CANONICAL_HARNESS_ADDRESSES)
        if trusted_harness_address:
            valid_emitters.add(str(trusted_harness_address).strip().lower())

        # Collect raw log events from structured JSON if not directly provided,
        # and discover any dynamic root test harness address from execution traces.
        extracted_raw_logs: List[Dict[str, Any]] = list(raw_logs or [])
        if structured_json and isinstance(structured_json, dict):
            for suite_name, suite_data in structured_json.items():
                if isinstance(suite_data, dict):
                    test_results = suite_data.get("test_results", {})
                    for test_name, test_data in test_results.items():
                        if isinstance(test_data, dict):
                            suite_logs = test_data.get("logs", [])
                            if isinstance(suite_logs, list):
                                for item in suite_logs:
                                    if isinstance(item, dict):
                                        extracted_raw_logs.append(item)
                            # Discover deployed test contract address from trace arena
                            traces = test_data.get("traces", [])
                            if isinstance(traces, list):
                                for stage in traces:
                                    if isinstance(stage, (list, tuple)) and len(stage) == 2 and isinstance(stage[1], dict):
                                        arena = stage[1].get("arena", [])
                                        if arena and isinstance(arena[0], dict):
                                            trace_node = arena[0].get("trace", {})
                                            root_addr = trace_node.get("address")
                                            if root_addr and isinstance(root_addr, str):
                                                valid_emitters.add(root_addr.strip().lower())

        # 1. Parse raw EVM event logs with cryptographic topic and emitter verification
        for rlog in extracted_raw_logs:
            if not isinstance(rlog, dict):
                continue

            emitter = str(rlog.get("address", "")).lower()
            topics = [str(t).lower() for t in rlog.get("topics", [])]
            data = str(rlog.get("data", ""))

            if not topics:
                continue

            topic0 = topics[0]

            # Check if event claims to be SecurityInvariantBreached
            if topic0 == TOPIC_SECURITY_INVARIANT_BREACHED:
                if emitter in valid_emitters:
                    has_genuine_harness_signal = True
                    invariant_type, event_deficit = _decode_abi_string_and_uint(data)
                    trace_context["event_emitted"] = "SecurityInvariantBreached"
                    trace_context["verified_emitter"] = emitter
                    trace_context["topic0"] = topic0
                    trace_context["verified_event"] = True
                    trace_context["invariant_type"] = invariant_type
                    trace_context["deficit"] = event_deficit
                    # Comprehensive invariant flags for all 12 vulnerability classes
                    typed_flags = {
                        "DEPOSITOR_SOLVENCY_COLLAPSE": ("isInsolvent", "depositor_solvency_collapse"),
                        "UNAUTHORIZED_ADMIN_DRAIN": ("unauthorized_admin", "owner_hijacked"),
                        "SHARE_INFLATION_DEPOSITOR_DILUTION": ("share_inflation_detected",),
                        "ERC4626_SHARE_DILUTION_OR_INFLATION": ("share_inflation_detected",),
                        "ORACLE_PRICE_MANIPULATION": ("price_manipulated",),
                        "FLASH_LOAN_REWARD_DISTORTION": ("reward_drained",),
                        "SIGNATURE_REPLAY_DRAIN": ("replay_executed",),
                        "STATE_ACCOUNTING_INCONSISTENCY": ("accounting_inconsistency",),
                        "BUSINESS_LOGIC_FEE_DRAIN": ("fee_drain",),
                        "LIQUIDATION_ACCOUNTING_DEFECT": ("bad_debt_created",),
                        "CROSS_CONTRACT_DESYNCHRONIZATION": ("cross_contract_desync",),
                        "DENIAL_OF_SERVICE_LIVENESS": ("dos_detected",),
                        "PRECISION_LOSS_FEE_BYPASS": ("precision_loss",),
                    }
                    for flag in typed_flags.get(invariant_type, ()):
                        trace_context[flag] = True
                else:
                    spoof_attempt_detected = True

            # Check if event is OracleSnapshot
            if topic0 == TOPIC_ORACLE_SNAPSHOT:
                if emitter == expected_harness:
                    has_genuine_harness_signal = True
                    # Decode structured snapshot payload if present
                    try:
                        clean_data = data.replace("0x", "")
                        # Try to extract JSON strings from ABI data
                        raw_bytes = bytes.fromhex(clean_data)
                        text_content = raw_bytes.decode("utf-8", errors="ignore")
                        match = re.search(r'\{.*\}', text_content)
                        if match:
                            parsed = json.loads(match.group(0))
                            initial_state.update(parsed.get("initial", {}))
                            final_state.update(parsed.get("final", {}))
                            trace_context.update(parsed.get("context", {}))
                    except Exception:
                        pass
                else:
                    spoof_attempt_detected = True

        # 2. Check decoded logs and raw text for spoofing attempts
        combined_text = (stdout_text or "") + "\n" + (stderr_text or "")
        combined_decoded = list(decoded_logs or [])

        for line in combined_decoded:
            l_str = str(line)
            if ("SecurityInvariantBreached" in l_str or "[INVARIANT_BREACHED" in l_str):
                # Console/decoded text is diagnostic only. It can never set an
                # invariant flag, deficit, owner, price, or other state value.
                if not has_genuine_harness_signal:
                    spoof_attempt_detected = True
            if "[ORACLE_SNAPSHOT:" in l_str:
                # Text snapshots are never accepted; only authenticated raw ABI logs count.
                spoof_attempt_detected = True

        # Check raw text for unconfirmed markers
        if ("[INVARIANT_BREACHED" in combined_text or "[ORACLE_SNAPSHOT:" in combined_text) and not has_genuine_harness_signal:
            spoof_attempt_detected = True

        return initial_state, final_state, trace_context, has_genuine_harness_signal, spoof_attempt_detected

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
        structured_json: Optional[Dict[str, Any]] = None,
        raw_logs: Optional[List[Dict[str, Any]]] = None,
        trusted_harness_address: Optional[str] = None
    ) -> VerificationResult:
        """
        Executes hardened, multi-factor EVM State verification.
        Enforces:
        1. Cheatcode isolation.
        2. Clean execution (no reverts).
        3. Anti-spoofing rejection of unconfirmed markers and wrong emitters.
        4. Target-specific invariant registry matching (Vault invariants never applied to unknown targets).
        5. True state-based / event-grounded evaluation without synthetic state fabrication.
        """
        execution_success = (return_code == 0 and (test_status == "Success" or test_status is None))

        # 1. Immediate rejection on cheatcodes
        if cheatcode_detected:
            return VerificationResult(
                execution_success=False,
                invariant_breach=False,
                replay_confirmed=False,
                confidence_status="REJECTED",
                failure_reason="Prohibited cheatcode detected in candidate exploit (vm.* / forge-std/Test.sol)",
                breached_invariants=[]
            )

        # 2. Immediate rejection if compilation or execution failed with revert
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

        # 3. Parse harness evidence with topic and emitter validation
        init_state, fin_state, trace_ctx, genuine_signal, spoof_detected = self.parse_harness_evidence(
            decoded_logs=decoded_logs,
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            structured_json=structured_json,
            raw_logs=raw_logs,
            trusted_harness_address=trusted_harness_address
        )

        # Requirement 2 & 3: Rejection on spoofing attempts
        if spoof_detected:
            return VerificationResult(
                execution_success=execution_success,
                invariant_breach=False,
                replay_confirmed=False,
                confidence_status="REJECTED",
                evidence=ExecutionEvidence(
                    execution_id=f"exec_{uuid.uuid4().hex[:8]}",
                    candidate_id=candidate_id,
                    target_id=target.name,
                    initial_state_hash=compute_state_hash(init_state),
                    final_state_hash=compute_state_hash(fin_state),
                    execution_status="FAILED",
                    execution_success=execution_success,
                    logs_reference=decoded_logs[:10] if decoded_logs else [],
                    environment_fingerprint={
                        "target_name": target.name,
                        "solc_version": "0.8.20",
                        "execution_time_sec": execution_time_sec
                    },
                    state_delta={
                        "initial_state": init_state,
                        "final_state": fin_state,
                        "has_real_snapshot": False,
                        "state_changed": False,
                        "trace_context": trace_ctx
                    }
                ),
                failure_reason="Security Violation: Spoofed invariant breach marker or unconfirmed snapshot detected",
                breached_invariants=[]
            )

        # Requirement 6 & 7: Resolve applicable invariants with precedence
        applicable_invariants = self.get_invariants_for_target(target.name)
        if not applicable_invariants:
            return VerificationResult(
                execution_success=execution_success,
                invariant_breach=False,
                replay_confirmed=False,
                confidence_status="REJECTED",
                failure_reason=f"No applicable security invariants registered for target class '{target.name}'",
                breached_invariants=[]
            )

        # Requirement 1: NO SYNTHETIC STATE CREATION!
        # Do not manufacture initial or final state. Use actual captured state dicts.
        init_hash = compute_state_hash(init_state)
        fin_hash = compute_state_hash(fin_state)

        state_delta = {
            "initial_state": init_state,
            "final_state": fin_state,
            "has_real_snapshot": bool(init_state or fin_state),
            "state_changed": (init_hash != fin_hash) if (init_state or fin_state) else False,
            "trace_context": trace_ctx
        }

        # Evaluate applicable invariants against actual state and verified trace context
        invariant_results: List[InvariantResult] = []
        breached_invariants: List[str] = []

        for inv in applicable_invariants:
            inv_res = inv.evaluate(init_state, fin_state, trace_ctx)
            invariant_results.append(inv_res)
            if not inv_res.passed:
                breached_invariants.append(inv.invariant_id)

        # Genuine invariant breach requires:
        # 1. Clean execution success (return_code == 0)
        # 2. Genuine harness signal verified by topic/emitter
        # 3. At least one invariant evaluated to breached
        invariant_breached = execution_success and genuine_signal and (len(breached_invariants) > 0)

        status = "PROVISIONAL_BREACH" if invariant_breached else "UNVERIFIED"

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
            logs_reference=decoded_logs[:10] if decoded_logs else [],
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
            failure_reason=None if invariant_breached else ("Trusted event did not establish a registered invariant breach; absence of evidence is not SAFE_RUN" if execution_success else revert_reason)
        )


# Global singleton instance
trusted_oracle = TrustedEVMStateOracle()
