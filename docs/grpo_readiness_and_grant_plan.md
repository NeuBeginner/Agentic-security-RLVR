# GRPO Readiness Audit & Compute Grant Plan

> **Audit Scope & Status**: `$0.00` Modal spend across PR #30–#34 (code audit, isolated PoC contour, and local verification); **`$0.26` live Modal `L4` PoC spend** across Stage 1 (`$0.24`) + Stage 2 (`$0.02`) on `poc_run_7543d0db` (`Qwen/Qwen3-4B-Instruct-2507`).  
> **Training Gate**: `TRAINING_STATUS = BLOCKED` by default in `core/config.py`, `core/grpo_trainer.py`, `modal_app.py`, `modal_grpo_poc_app.py`, and `benchmarks/run_grpo_poc.py` (temporarily unblocked only for the isolated 4-step `L4` Stage 2 PoC via `with_options(secrets=...)`, remaining fail-closed by default).  
> **Reference Benchmark Artifact**: `benchmarks/artifacts/run_1795027271_8c19acf` (`cycle8`, `baseline_5`).  
> **Metered Modal Balance**: **`$13.43` credits used** of `$20.00` total credit (`$6.57` remaining; total cost of live `L4` Stage 1+2 PoC = `$0.26`).

---

## 1. Executive Summary

The offline GRPO trainer (`core/grpo_trainer.py`), trajectory schema (`core/evaluator.py`, `core/schemas.py`), and evidence-scoped Reward v2.0.0 (`core/config.py`, `core/reward_shaping.py`) are **structurally compatible** with the inference and sandbox payloads produced in `cycle8` (`run_1795027271_8c19acf`).

However, **production H100 GRPO training still requires a compute grant** (`$6.57` remaining of `$20.00` credit after `$13.43` total used), while **end-to-end `L4` PoC feasibility (Stage 1 + Stage 2) is now empirically verified**:

1. **Data Isolation & `G >= 4` Rollout Collection — RESOLVED & VERIFIED (PR #31 + Stage 1 PoC `poc_run_7543d0db`)**: Added 40 disjoint `train` contracts in `benchmarks/targets/solidity_train/`, `benchmarks/train_dataset.json`, and `core/train_rollout_collector.py` with strict test-overlap checks and a `G >= 4` temperature schedule. Live Stage 1 on `L4` persisted `16/16` rollouts (`0` `INFRA_ERROR`, `3` `EXPLOIT_CONFIRMED` via Foundry, `2/4` `informative_groups`).
2. **GPU Tier & Base Model Accessibility — RESOLVED & VERIFIED (PR #32 + PR #33 + Stage 2 PoC `poc_run_7543d0db`)**: Configured `bitsandbytes` alongside `peft`/`trl` in GPU images, preserved `GRPO_GPU_TYPE = "H100"` for production, and verified `modal_grpo_poc_app.py` (`L4`, `scaledown_window=60`) end-to-end with `Qwen/Qwen3-4B-Instruct-2507` (Stage 2 LoRA GRPO completed `steps_completed=4`).
3. **Fail-Closed Training Gate & Budget — INTENTIONALLY ACTIVE**: `TRAINING_STATUS = BLOCKED` remains strictly enforced by default (`core/config.py`); actual metered Modal billing is **`$13.43` used / `$20.00` (`$6.57` remaining; live `L4` Stage 1+2 PoC cost `$0.26`)**, which is insufficient for production `H100` multi-GPU-hour GRPO training + post-training R4 evaluation without a compute grant.

---

## 2. Local Schema Compatibility Audit (`cycle8` vs `core/grpo_trainer.py`)

A local `$0.00` compatibility check was executed against all 16 target stage-evidence files in `benchmarks/artifacts/run_1795027271_8c19acf/baseline_5/`:

- **Inference fields (`*_stage_evidence_inference.json`)**: All 16/16 targets contain:
  - `prompt_text` (7,876–10,397 chars) with explicit `<|im_start|>system` and `<|im_end|>` chat-template markers.
  - `generated_token_ids` (109–2,048 integer token IDs; `SAFE-02` hit the 2,048-token cap with `GENERATION_FORMAT_ERROR`).
  - `raw_model_response` (487–7,939 chars) and `test_code`.
- **Reward fields (`*_stage_evidence_evm_sandbox.json` + `<TARGET>.json`)**: All 16/16 targets carry `reward_score`, `reward_components` (`generation`, `compilation`, `verification`, `invariant`, `replay`), and `reward_spec_version = "2.0.0"`.
- **Eligibility & Tokenization Check**:
  - When packaged via `core/evaluator.py:create_trajectory_record` (`L434-L502`) with the current `adapters.py` flags (`dataset_split="test"`, `dataset_partition="test"`, `trainable=False`), `evaluate_trajectory_eligibility` (`core/grpo_trainer.py:L616-L775`) **rejects 16/16** with `partition_mismatch_test`.
  - When packaged with training flags (`dataset_split="train"`, `dataset_partition="production"`, `is_synthetic=False`, `trainable=True`), **16/16** pass `evaluate_trajectory_eligibility` (`is_eligible=True`, `exact_token_eligible=True`) and `prepare_rollout_tokens(..., max_seq_len=4096)` (`core/grpo_trainer.py:L252-L388`) without triggering `RolloutTooLongError` or `UnsafeRolloutError` (total sequence lengths ~2,803–4,096 tokens).

---

## 3. Technical Blockers & Resolution Status

### Blocker 1: `train` / `test` Data Isolation & Non-Degenerate Groups (`informative_groups`) — **RESOLVED in code (PR #31)**

- **Implemented Solution**:
  1. Added a dedicated `train` split of 10 Solidity contracts in `benchmarks/targets/solidity_train/` and `benchmarks/train_dataset.json`, **disjoint from the 16 benchmark targets** in `baseline_5` (enforced by `core/train_rollout_collector.py::validate_train_target_isolation`).
  2. `core/train_rollout_collector.py::collect_train_rollouts` persists both verified exploits and failed rollouts (excluding `INFRA_ERROR`) with a `G >= 4` temperature schedule (`4 <= group_size <= 8`) and computes `diagnose_group_spread(groups)`.
  3. Training rollouts are tagged with `dataset_partition="production"`, `dataset_split="train"`, `trainable=True`, `is_synthetic=False`, `token_provenance="model_generate"`, and non-empty `generated_token_ids`.

### Blocker 2: GPU Hardware (`T4` vs `L4` / `H100`) & Base Model Availability — **RESOLVED in code (PR #32 + PR #33)**

- **Implemented Solution**:
  1. `core/config.py` configures `GRPO_BASE_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"` (publicly accessible, un-gated), `GRPO_GPU_TYPE = "H100"` for production GRPO, and isolated PoC settings `GRPO_POC_GPU_TYPE = "L4"`, `GRPO_POC_TRAJECTORY_DIR = "/vol/models/trajectories_grpo_poc"`, `GRPO_POC_CHECKPOINT_DIR = "/vol/models/checkpoints_grpo_poc"`.
  2. Both `modal_app.py::gpu_image` and `modal_grpo_poc_app.py::poc_gpu_image` include `torch`, `transformers>=4.40.0`, `accelerate>=0.28.0`, `peft>=0.14.0`, `trl>=0.14.0`, and `bitsandbytes>=0.45.0`.
  3. `modal_grpo_poc_app.py` (`aegis-rlvr-grpo-poc`) isolates L4 PoC execution from the R1-guarded production `modal_app.py`, with `min_containers=0, buffer_containers=0, scaledown_window=60` on all GPU functions and `block_network=True` on `poc_verify_train_exploit`.

### Blocker 3: Fail-Closed Security Gate (`TRAINING_STATUS = BLOCKED`) & Budget — **INTENTIONALLY ACTIVE**

- `core/config.py`, `core/grpo_trainer.py`, `modal_app.py`, `modal_grpo_poc_app.py`, and `benchmarks/run_grpo_poc.py` enforce `is_training_blocked(config)` fail-closed at both client and server boundaries by default.
- Actual metered Modal billing is **`$13.43 / $20.00`** used (**`$6.57` remaining**; live `L4` Stage 1+2 PoC total cost = **`$0.26`**). Production `H100` training remains **BLOCKED** by default until explicit budget/grant approval is obtained.

---

## 4. Verified Benchmark Baseline (`cycle4`–`cycle8`) & Grant Compute Plan

### 4.1 Verified Benchmark Progression (`baseline_5`, 16 Targets: 12 Vulnerable + 4 Safe Controls)

| Cycle | Run ID | TP / Vuln | TN / Safe | FP | Recall | Precision | F1 | Replay Rate | Avg Duration / Target |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `cycle4` | `run_1794945167_fdb1b2d` | 3 / 12 | 4 / 4 | 0 | 25.00% | 100.00% | 0.4000 | 100.00% | 18.68s |
| `cycle5` | `run_1794998302_d2d05e5` | 5 / 12 | 4 / 4 | 0 | 41.67% | 100.00% | 0.5883 | 100.00% | 46.23s |
| `cycle6` | `run_1795014999_12a1178` | 5 / 12 | 4 / 4 | 0 | 41.67% | 100.00% | 0.5883 | 100.00% | 28.19s |
| `cycle7` | `run_1795023810_524533d` | 6 / 12 | 4 / 4 | 0 | 50.00% | 100.00% | 0.6667 | 100.00% | 36.15s |
| `cycle8` | `run_1795027271_8c19acf` | 6 / 12 | 4 / 4 | 0 | 50.00% | 100.00% | 0.6667 | 100.00% | 33.55s |

- **Observed Modal Billing Facts**:
  - Total Modal credit: `$20.00`.
  - Observed cost per full R4 benchmark run (`baseline_5`, 16 targets): `$1.11–$1.38`.
  - Observed cost of live `L4` Stage 1 + Stage 2 PoC (`poc_run_7543d0db`, `Qwen/Qwen3-4B-Instruct-2507`): **`$0.26`** (`$0.24` Stage 1 + `$0.02` Stage 2).
  - Current metered billing: **`$13.43` credits used** (**`$6.57` remaining** of `$20.00`).

### 4.2 Compute Budget Plan & Verified L4 PoC Results

#### (A) Stage 1 & Stage 2 Micro-PoC on `L4` (`Qwen/Qwen3-4B-Instruct-2507`, isolated `aegis-rlvr-grpo-poc`) — **COMPLETED (`poc_run_7543d0db`, `$0.26` total)**
- **Stage 1 (`collect-and-diagnose`, `$0.24`, `TRAINING_STATUS = BLOCKED`)**: Executed `modal_grpo_poc_app.py` via `benchmarks/run_grpo_poc.py --stage collect-and-diagnose` (`benchmarks/evidence/grpo_poc/poc_collect-and-diagnose_20261120T092513Z.json`) on `L4` with `Qwen/Qwen3-4B-Instruct-2507`:
  - `16/16` rollouts persisted (`4` groups × `G=4`), `0` `INFRA_ERROR`, `3` `EXPLOIT_CONFIRMED` (reproduced via Foundry).
  - `2/4` `informative_groups` (`mean_abs_advantage=0.4663`), finite `diagnostic_loss=0.5678`, `optimizer_step_executed=false`, `weights_updated=false`, `checkpoints_created=false`.
- **Stage 2 (`train`, 1 epoch / 4 steps, `$0.02`, explicit PoC unblock)**: Executed `benchmarks/run_grpo_poc.py --stage train` (`benchmarks/evidence/grpo_poc/poc_train_20261120T101305Z.json`) on `L4` with `Qwen/Qwen3-4B-Instruct-2507`:
  - LoRA GRPO completed (`steps_completed=4`), non-zero KL divergence observed (`0.000387` at step 3, `0.000186` at step 4), and checkpoint saved to `/vol/models/checkpoints_grpo_poc/checkpoint-step-4`.

#### (B) Production GRPO on `H100 80 GB` (Grant Application Scope)
- **Goal**: Scale GRPO LoRA/QLoRA training using **`Qwen/Qwen3-Coder-30B-A3B-Instruct`** (public MoE 30B/3B) as the priority open-weight replacement for the closed `qtum/Qwen3-Coder-30B-A3B-Audit` checkpoint—building on **`Qwen/Qwen3-4B-Instruct-2507`** as the verified `L4` PoC baseline (and optionally comparing 14B–32B dense coding checkpoints such as `Qwen/Qwen2.5-Coder-14B-Instruct` / `Qwen/Qwen2.5-Coder-32B-Instruct`)—to push `baseline_5` recall beyond the `50.00%` (`6/12`) ceiling while preserving `100.00%` precision (`0 FP`) and `100.00%` independent replay.
- **Estimated Compute (Grant Sizing)**:
  - **Model Prefetch & Validation**: 1× cold download of public checkpoint to Modal Volume + `diagnostic_grpo_forward_remote` on `H100`.
  - **Training Rollout Collection**: 40–60 disjoint `train` contracts × `G = 4–8` candidates (160–480 rollouts) at ~33.55s/target baseline inference+sandbox cadence -> ~1.5–4.5 `H100` GPU-hours (plus CPU Foundry replay).
  - **GRPO LoRA/QLoRA Training**: 2–3 epochs over informative groups (`GRPO_GROUP_SIZE=4`, `GRPO_MAX_SEQ_LEN=4096`, `old_logprobs` + `ref_logprobs` pre-pass + backward pass) -> ~2–4 `H100` GPU-hours per training experiment (budgeting 3–5 iterations/ablations = ~6–20 `H100` GPU-hours).
  - **Evaluation Runs**: 5–10 R4 benchmark runs (`$1.11–$1.38` observed each) -> `$5.55–$13.80`.
  - **Recommended Grant Request**: `~15–30 H100 GPU-hours` + `$15–$25` Foundry/CPU & evaluation buffer (total grant target scaled to Modal's current `H100` per-second rate at submission time).

---

## 5. Current Implementation & Preflight Verification Status (`$0.00`)

- **Disjoint Train Split & Collector**: `benchmarks/train_dataset.json`, `benchmarks/targets/solidity_train/`, and `core/train_rollout_collector.py` (40 train contracts validated with zero overlap against the 16 `baseline_5` test targets).
- **Isolated L4 PoC App & Fail-Closed Driver**: `modal_grpo_poc_app.py` (`aegis-rlvr-grpo-poc`) and `benchmarks/run_grpo_poc.py` (requires `AEGIS_APPROVE_GRPO_POC=1` for live calls; `--stage train` blocked client- and server-side while `TRAINING_STATUS = BLOCKED`; `scaledown_window=60`, `min_containers=0`, `buffer_containers=0`).
- **Zero-Cost Preflight Commands**:
  - `python -m benchmarks.run_grpo_poc --dry-run` (validates all 40 train targets locally and prints the L4 execution plan for `$0.00`).
  - `python -m pytest -q tests/test_grpo_poc_driver.py tests/test_grpo_modal_prep.py tests/test_r1_dispatch_contract.py tests/test_r1_bounds_contract.py tests/test_train_rollout_collector.py`
  - `python -m benchmarks.validate_consolidated_closure_evidence --check`
- *Verified Live `L4` PoC Artifacts (`poc_run_7543d0db`, `$0.26` total)*:
  - Stage 1 (`$0.24`): `benchmarks/evidence/grpo_poc/poc_collect-and-diagnose_20261120T092513Z.json`
  - Stage 2 (`$0.02`): `benchmarks/evidence/grpo_poc/poc_train_20261120T101305Z.json`
