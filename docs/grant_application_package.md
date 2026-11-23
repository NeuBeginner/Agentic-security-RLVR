# Aegis-RLVR 2.0 — Grant Application & Technical Evidence Package (`v2.1.0`)

> **Target Programs**: Ethereum Foundation Ecosystem Support Program (ESP), Optimism RetroPGF / Grants, Arbitrum Foundation Grants, Modal Compute Credits.  
> **Repository**: `https://github.com/NeuBeginner/Agentic-security-RLVR`  
> **Current Modal Balance**: **`~$18–$19` credits used** of `$30.00` starting credits (**`~$11–$12` remaining**; frozen ahead of H100 compute grant).

---

## 1. Executive Summary & Problem Statement

Static LLM smart-contract auditors suffer from two structural failures:
1. **Unverified hallucinations & high false-positive rates**: models emit plausible vulnerability descriptions without proving exploitability on an actual EVM.
2. **No closed-loop remediation**: static auditors neither synthesize unprivileged on-chain PoCs nor verify that proposed patches block the exploit without breaking legitimate protocol functionality.

**Aegis-RLVR 2.0** solves both gaps by coupling **deterministic Foundry EVM invariant verification**, strict anti-cheatcode barriers (`vm.*` / `forge-std` / `selfdestruct` rejection), and **Dual-Loop Red + Blue Reinforcement Learning from Verifiable Rewards (RLVR / GRPO)**:
- **Red Loop (`Reward v2.0.0`)**: synthesizes unprivileged `ExploitModule` PoCs, executes them against immutable repository-owned `*Harness.t.sol` oracles, and confirms deterministic reproducibility via independent fresh-EVM replay.
- **Blue Loop (`BlueReward 1.0.0`)**: consumes confirmed Red exploits, synthesizes minimal Solidity patches, enforces a 5-stage fail-closed verification pipeline (static & anti-cheatcode gate, Red precondition check, `*Functional.t.sol` regression gate, `*Harness.t.sol` exploit-blocked gate, independent replay), and penalizes trivial `revert()` bricking patches (`FUNCTIONAL_REGRESSION = -0.25`).

---

## 2. Verified Technical Achievements (`v2.1.0`)

All figures below are backed by retained execution artifacts in this repository (`0` fabricated metrics, `0` skipped CI gates).

### 2.1 Aegis-EVM-Bench (56 Verified Solidity Contracts)
Implemented in [`benchmarks/aegis_evm_bench.py`](../benchmarks/aegis_evm_bench.py) (`inspect`, `evaluate`, `leaderboard`):
- **Frozen `test` split (`16` targets)**: `12` vulnerable DeFi vulnerability classes + `4` `SYNTHETIC_SAFE_CONTROL` contracts (`benchmarks/benchmark_dataset.json`, `benchmarks/targets/solidity/`).
- **Disjoint `train` split (`40` targets)**: `40` distinct DeFi vulnerability classes (`benchmarks/train_dataset.json`, `benchmarks/targets/solidity_train/`).
- **Cryptographic isolation**: `SHA-256 overlap (train ∩ test) == 0`, `name_overlap == 0` (enforced by `inspect` and `core/train_rollout_collector.py`).
- **Dual-Loop Patch Pilots (`5` targets)**: trusted functional regression suites in `benchmarks/targets/solidity_train_functional/` (`TrainAdminTreasury`, `TrainShareVault`, `TrainReentrancyBank`, `TrainUninitializedVault`, `TrainTimelockBypass`).

### 2.2 Frontier `baseline_5` Progression (`test` Split, `cycle4`–`cycle8`)
Reference artifact: [`benchmarks/artifacts/run_1795027271_8c19acf/summary.json`](../benchmarks/artifacts/run_1795027271_8c19acf/summary.json) (`qtum/Qwen3-Coder-30B-A3B-Audit`, 16 targets):

| Cycle | Run ID | TP / Vuln | TN / Safe | FP | Recall | Precision | F1 | Replay Rate |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `cycle4` | `run_1794945167_fdb1b2d` | 3 / 12 | 4 / 4 | 0 | 25.00% | 100.00% | 0.4000 | 100.00% |
| `cycle5` | `run_1794998302_d2d05e5` | 5 / 12 | 4 / 4 | 0 | 41.67% | 100.00% | 0.5883 | 100.00% |
| `cycle6` | `run_1795014999_12a1178` | 5 / 12 | 4 / 4 | 0 | 41.67% | 100.00% | 0.5883 | 100.00% |
| `cycle7` | `run_1795023810_524533d` | 6 / 12 | 4 / 4 | 0 | 50.00% | 100.00% | 0.6667 | 100.00% |
| `cycle8` | `run_1795027271_8c19acf` | **6 / 12** | **4 / 4** | **0** | **50.00%** | **100.00%** | **0.6667** | **100.00%** |

Consolidated closure validation ([`benchmarks/evidence/consolidated_closure_validation_evidence.json`](../benchmarks/evidence/consolidated_closure_validation_evidence.json)): **21/21 checks PASSED**. *(Note: only `baseline_5` progression is claimed; a full 5-baseline comparative sweep is outside this report.)*

### 2.3 Controlled L4 Mini-GRPO + Verifier-Guided Refinement (`Qwen/Qwen3-4B-Instruct-2507`)
Trained on `poc_40t_train32` (`32` disjoint train targets, `126` rollouts, `23/31` informative groups, `checkpoint-step-69`, `3` epochs × `23` steps, `lr=1e-5`, `max_kl=0.0098`, `0` NaNs) and evaluated on `8` held-out `DEV_EVAL_8` targets ([`benchmarks/evidence/grpo_poc/poc_40t_dev_3way_summary.json`](../benchmarks/evidence/grpo_poc/poc_40t_dev_3way_summary.json)):

| Stage (`DEV_EVAL_8`, 8 contracts × `G=4`) | `FORMAT_ERR` | Valid EVM (`EXP+REV+SAFE`) | `EXPLOIT_CONFIRMED` (Pass@1) | Mean Reward v2 |
| :--- | :---: | :---: | :---: | :---: |
| 1. Pre-GRPO Base 4B (`R0`) | 13 / 32 (40.6%) | 18 / 32 (56.25%) | 2 / 32 (6.25%) | `-0.1922` |
| 2. Post-GRPO `step-69` (`R0`) | **2 / 32 (6.25%)** | 24 / 32 (75.00%) | 3 / 32 (9.38%) | `-0.1438` |
| 3. Post-GRPO `step-69` + Verifier `R1` | 3 / 32 (9.38%) | **26 / 32 (81.25%)** | **5 / 32 (15.63%, 2.5×)** | **`-0.0641`** |

- `0 INFRA_ERROR` across all 96 rollouts (`32` × `3` stages).
- `TrainShareVault` (high difficulty) reached `4/4` (`+1.0000`) with R1; `2/3` rollouts improved by Round 1 (`FOUNDRY EVM EXECUTION FEEDBACK`) converted directly to `EXPLOIT_CONFIRMED`.

### 2.4 Live E2E Dual-Loop Demo: «Red LLM Exploit → Blue LLM Verified Patch» (`dual_loop_poc_3t`)
Executed on Modal `L4` (`Qwen/Qwen3-4B-Instruct-2507`, ~7 min, [`benchmarks/evidence/dual_loop_poc/dual_loop_patch_dual_loop_poc_3t_20261123T095314Z.json`](../benchmarks/evidence/dual_loop_poc/dual_loop_patch_dual_loop_poc_3t_20261123T095314Z.json)):

| Target | Red Source Trajectory (`EXPLOIT_CONFIRMED`) | Blue Outcome | Reward | Functional Pass | Exploit Blocked | Replay |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| `TrainAdminTreasury` | `traj_poc_40t_train32_c4606d14` | **`PATCH_VERIFIED`** | **`+1.00`** | `true` | `true` | `true` |
| `TrainUninitializedVault` | `traj_poc_40t_train32_0d6ce899` | **`PATCH_VERIFIED`** | **`+1.00`** | `true` | `true` | `true` |
| `TrainShareVault` | `traj_poc_40t_dev_post_r1_9a025d5b` | `EXPLOIT_STILL_SUCCEEDS` | `-0.10` | `true` | `false` | `false` |

- **Summary**: **`2 / 3` (`66.7%`) `PATCH_VERIFIED (+1.0)`**, `mean_blue_reward = +0.2667`, `improved_by_refinement_count = 3`, **`0` compilation errors**, **`0` functional regressions**, **`0` infra errors**.
- **Honest 4B ceiling**: on `TrainShareVault`, the 4B model preserved functionality (`functional_pass=true`) without cheatcodes, but lacked the ERC4626 virtual-offset mathematical reasoning needed to block share inflation — directly motivating scaling the already-proven Dual-Loop RLVR pipeline to `Qwen/Qwen3-Coder-30B-A3B-Instruct` on `H100`.

---

## 3. Compute Grant Budget & 4-Milestone Roadmap (`H100 80 GB`)

- **Priority Base Model**: `Qwen/Qwen3-Coder-30B-A3B-Instruct` (open-weight MoE 30B/3B).
- **Current Account Status**: `~$18–$19` used of `$30.00` starting Modal credits (`~$11–$12` remaining, frozen).
- **Requested Compute Grant**: **`15–30 H100 GPU-hours`** + **`$15–$25` CPU/Foundry evaluation buffer**.

| Milestone | Scope | Deliverable & Success Metric |
| :--- | :--- | :--- |
| **M1 — 30B Rollout Collection** | Collect `R0 + R1` Red trajectories across all `40` disjoint `train` contracts (`G=4–8`) on `H100` + Foundry CPU | `160–320` verified rollouts (`0` `INFRA_ERROR`, high `EXPLOIT_CONFIRMED` group coverage) |
| **M2 — Red GRPO Policy** | Train LoRA/QLoRA GRPO on `H100` and evaluate on frozen `test` split (`16` targets) | Break `baseline_5` `50.00%` (`6/12`) Recall ceiling while maintaining `100.00%` Precision (`0%` FP) and `100%` Replay |
| **M3 — Blue Patch GRPO Policy** | Expand `*Functional.t.sol` suite to `20+` DeFi classes and train Blue patch-synthesis GRPO | Verified autonomous patch rate significantly above `4B` (`2/3`) on unseen vulnerability classes |
| **M4 — Public Release** | Publish LoRA weights, updated `Aegis-EVM-Bench` leaderboard, and technical report | Full reproducible artifacts & open-source release |

---

## 4. Zero-Cost Reviewer Reproducibility Checklist (`$0.00`)

Every architectural invariant, isolation proof, and Foundry verification gate can be reproduced locally at `$0.00` Modal cost:

```bash
# 1. Verify 56-contract corpus & train/test SHA-256 overlap == 0
python -m benchmarks.aegis_evm_bench inspect

# 2. Render verified benchmark & GRPO progression leaderboards from repo artifacts
python -m benchmarks.aegis_evm_bench leaderboard

# 3. Run Dual-Loop Red+Blue patch verification & Aegis-EVM-Bench tests (unit + real Foundry)
python -m pytest -v tests/test_patch_verifier.py tests/test_patch_poc.py tests/test_aegis_evm_bench.py

# 4. Validate consolidated 21/21 closure evidence
python -m benchmarks.validate_consolidated_closure_evidence --check
```
