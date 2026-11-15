# Benchmark Methodology and Evidence Status

## Dataset (16 Targets: 12 Vulnerable + 4 Safe Controls)

The benchmark dataset (`benchmarks/benchmark_dataset.json`) contains **12 vulnerable Solidity target classes** and **4 synthetic safe controls** stored under `benchmarks/targets/solidity/`. Every target is paired with an immutable, repository-owned Foundry harness registered in `TRUSTED_HARNESS_CONTRACTS` (`sandbox/runner.py`):

### Vulnerable Targets (12)
1. `Vault` (`VaultHarness.t.sol` / `VaultTrustedHarness`) — Reentrancy solvency drain
2. `ERC4626Vault` (`ERC4626VaultHarness.t.sol` / `ERC4626TrustedHarness`) — ERC4626 first-depositor share inflation dilution
3. `AccessControlVault` (`AccessControlVaultHarness.t.sol` / `AccessControlVaultHarness`) — Unprotected initializer / ownership takeover
4. `AuctionDoS` (`AuctionDoSHarness.t.sol` / `AuctionDoSHarness`) — Push-refund denial of service on outbid
5. `CrossContractBridge` (`CrossContractBridgeHarness.t.sol` / `CrossContractBridgeHarness`) — Unauthenticated cross-chain message execution
6. `FeeShareYieldVault` (`FeeShareYieldVaultHarness.t.sol` / `FeeShareYieldVaultHarness`) — Fee calculation precision loss / fee evasion
7. `FlashLoanRewardPool` (`FlashLoanRewardPoolHarness.t.sol` / `FlashLoanRewardPoolHarness`) — Instantaneous flash-deposit reward capture
8. `LendingLiquidation` (`LendingLiquidationHarness.t.sol` / `LendingLiquidationHarness`) — Unchecked liquidation bonus over-seizure
9. `OracleLendingPool` (`OracleLendingPoolHarness.t.sol` / `OracleLendingPoolHarness`) — Spot-AMM price oracle manipulation
10. `PrecisionStakingPool` (`PrecisionStakingPoolHarness.t.sol` / `PrecisionStakingPoolHarness`) — Reward-index rounding / stake amplification
11. `RewardDistributorLogic` (`RewardDistributorLogicHarness.t.sol` / `RewardDistributorLogicHarness`) — Storage slot collision via `delegatecall`
12. `SignatureReplayWallet` (`SignatureReplayWalletHarness.t.sol` / `SignatureReplayWalletHarness`) — Missing nonce / cross-call signature replay

### Safe Controls (4)
1. `SecureVault` (`SecureVaultHarness.t.sol` / `SecureVaultTrustedHarness`) — Sentinel: `EXPLOIT_FAILED: SecureVault invariant held`
2. `SecureERC4626Vault` (`SecureERC4626VaultHarness.t.sol` / `SecureERC4626TrustedHarness`) — Sentinel: `EXPLOIT_FAILED: SecureERC4626Vault virtual offset invariant held`
3. `SecureAccessControlVault` (`SecureAccessControlVaultHarness.t.sol` / `SecureAccessControlVaultHarness`) — Sentinel: `EXPLOIT_FAILED: SecureAccessControlVault access control held`
4. `SecureOraclePool` (`SecureOraclePoolHarness.t.sol` / `SecureOraclePoolHarness`) — Sentinel: `EXPLOIT_FAILED: SecureOraclePool TWAP oracle invariant held`

## Modes

- `--mode smoke` executes the deterministic `SyntheticSmokeAdapter` fixture used only to verify report shape, metric calculations, CI plumbing, and schema compatibility. Smoke outputs are explicitly flagged (`is_synthetic_smoke: true`, `execution_mode: "SYNTHETIC_SMOKE_TEST"`) and must never be described as empirical results.
- `--mode real` executes the five distinct baseline adapters (`SlitherBaselineAdapter`, `LLMAuditorBaselineAdapter`, `LLMUnverifiedPoCBaselineAdapter`, `LLMNaiveFoundryBaselineAdapter`, and `FullAegisRLVRBaselineAdapter`).
  - Adapter execution receives **only** the public `TargetSpecification` (`benchmarks/protocol.py`); `GroundTruth` labels are strictly isolated for post-run confusion-matrix evaluation (`benchmarks/evaluator.py`).
  - Missing tools, missing API keys, or unapproved Modal GPU dispatch fail closed with explicit `UNAVAILABLE`, `FAILED`, or `INCOMPLETE` statuses and `null` empirical ratios (`precision`, `recall`, `f1_score`).
  - Remote Modal execution (`baseline5_provider` in `{"modal_h100", "modal_t4"}`) is gated by `DispatchGate` (`benchmarks/r1_dispatch.py`), which enforces `core/r1_bounds.py` and requires a cryptographically verified maintainer approval artifact (`core/r1_approval.py`) matching the complete dispatch envelope before any `.remote()` or `.map()` call can occur.

## Local Real Foundry Verification

All 16 repository targets and their immutable harnesses are verified end-to-end against real local Foundry (`forge test --offline --json -vvvv` with `forge 1.9.0` and `solc 0.8.20`) in `tests/test_real_foundry_e2e_all_targets.py`, producing the reproducible verification artifact `benchmarks/evidence/real_foundry_16_target_verification.json` (12/12 vulnerable targets breached and confirmed via independent replay; 4/4 safe controls held with exact sentinel revert strings).
