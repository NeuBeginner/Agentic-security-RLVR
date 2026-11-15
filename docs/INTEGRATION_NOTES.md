# Reconciled MiniMax + Antigravity Integration Notes

This repository integrates MiniMax's proof-based Solidity contract normalization (`core/llm_generator.py`), immutable structured-harness verification (`core/evidence.py`, `sandbox/runner.py`), and Reward Specification 2.0.0 (`core/reward_shaping.py`) with the 16-target multi-baseline benchmark suite, secondary EVM State Oracle (`core/evm_oracle.py`), and R1 bounded Modal dispatch gate (`core/r1_bounds.py`, `core/r1_approval.py`, `benchmarks/r1_dispatch.py`).

## Key Subsystems

1. **Findings-to-Hypotheses Pipeline (`core/hypothesis_manager.py`):**
   - Normalizes raw static-analysis or auditor findings into prioritized `AttackHypothesis` records with deduplication, severity ranking, and feedback lifecycle tracking.
2. **16-Target Trusted Harness Allowlist (`sandbox/runner.py`):**
   - All 12 vulnerable targets and 4 safe controls in `benchmarks/targets/solidity/` are registered in `TRUSTED_HARNESS_CONTRACTS`.
   - Harnesses are loaded exclusively from the repository-owned trusted directory (never from runtime candidate payloads).
   - Every harness implements `testExploit()`, returning normally only when the target's security invariant is breached and reverting with `EXPLOIT_FAILED: ...` when the invariant holds.
3. **Authoritative Verdict vs. Secondary EVM State Oracle (`core/evidence.py`, `core/evm_oracle.py`):**
   - The structured result of the immutable harness suite (`HARNESS_VERDICT_BREACH`, `HARNESS_VERDICT_NO_BREACH`, `HARNESS_VERDICT_EXEC_REVERT`, `HARNESS_VERDICT_UNKNOWN`) is the **sole authority** for Reward Specification 2.0.0 scoring.
   - `TrustedEVMStateOracle` (`core/evm_oracle.py`) operates over raw Foundry transaction logs emitted strictly by the deployed trusted harness address (`trusted_harness_address`). It decodes ABI-encoded `OracleSnapshot(string,string,string)` events (as well as single-string ABI tuples and raw JSON hex payloads) and `SecurityInvariantBreached` events to evaluate formal target-specific state invariants (`core/invariants.py`).
   - Unknown target names, untrusted log emitters, and malformed ABI event payloads fail closed (`oracle_snapshot_decode_error: True`, `has_genuine_harness_signal: False`).
4. **R1 Pre-Dispatch Bounds & Cryptographic Approval Gate (`core/r1_bounds.py`, `core/r1_approval.py`, `benchmarks/r1_dispatch.py`):**
   - Enforces hard ceilings on targets (`16` allowlisted contracts), baselines (`baseline_1`..`baseline_5`), GPU containers (`ProductionAuditAgent` on H100, `DevAuditAgent` on T4, CPU sandbox workers), generation parameters, volume mount path (`/vol/models`), and pinned toolchain (`solc 0.8.20`, `forge 1.9.0`).
   - `DispatchGate` refuses any remote Modal invocation unless a maintainer-signed approval artifact (`schema: aegis-rlvr/r1-approval/1`) matches the complete dispatch envelope and passes `verify_approval()`.
