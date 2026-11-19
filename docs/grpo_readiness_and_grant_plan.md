# GRPO Readiness Audit & Compute Grant Plan

> **Audit Scope & Status**: `$0.00` Modal spend across PR #30–#34 (code audit, isolated PoC contour, and local verification only).  
> **Training Gate**: `TRAINING_STATUS = BLOCKED` (fail-closed in `core/config.py`, `core/grpo_trainer.py`, `modal_app.py`, `modal_grpo_poc_app.py`, and `benchmarks/run_grpo_poc.py`).  
> **Reference Benchmark Artifact**: `benchmarks/artifacts/run_1795027271_8c19acf` (`cycle8`, `baseline_5`).  
> **Metered Modal Balance**: `$15.8675` spent of `$20.00` initial credit after `cycle8`; **`$4.1325` remaining**.

---

## 1. Executive Summary

The offline GRPO trainer (`core/grpo_trainer.py`), trajectory schema (`core/evaluator.py`, `core/schemas.py`), and evidence-scoped Reward v2.0.0 (`core/config.py`, `core/reward_shaping.py`) are **structurally compatible** with the inference and sandbox payloads produced in `cycle8` (`run_1795027271_8c19acf`).

However, **real GRPO training cannot be executed yet** due to three concrete technical blockers and a depleted initial credit balance (`$4.13` remaining of `$20.00`):

1. **Data Isolation & `G >= 4` Rollout Collection — RESOLVED in code (PR #31)**: Added 10 disjoint `train` contracts in `benchmarks/targets/solidity_train/`, `benchmarks/train_dataset.json`, and `core/train_rollout_collector.py` with strict test-overlap checks and a `G >= 4` temperature schedule.
2. **GPU Tier & Base Model Accessibility — RESOLVED in code (PR #32 + PR #33)**: Set `GRPO_BASE_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"`, added `bitsandbytes` alongside `peft`/`trl` in GPU images, preserved `GRPO_GPU_TYPE = "H100"` for production, and added the isolated L4 PoC app (`modal_grpo_poc_app.py`) with `GRPO_POC_GPU_TYPE = "L4"` and `scaledown_window=60`.
3. **Fail-Closed Training Gate & Budget — INTENTIONALLY ACTIVE**: `TRAINING_STATUS = BLOCKED` remains strictly enforced; actual metered Modal spend after `cycle8` is `$15.8675 / $20.00` (remaining balance strictly `$4.1325`; PR #30–#34 spent `$0.00`), which is sufficient for a 1.5B L4 micro-PoC (`< $1` Stage 1) but insufficient for production multi-GPU-hour GRPO training + post-training R4 evaluation without a compute grant.

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

- `core/config.py`, `core/grpo_trainer.py`, `modal_app.py`, `modal_grpo_poc_app.py`, and `benchmarks/run_grpo_poc.py` enforce `is_training_blocked(config)` fail-closed at both client and server boundaries.
- Actual metered Modal spend after `cycle8` is **`$15.8675 / $20.00`** (remaining balance strictly **`$4.1325`**; PR #30–#34 spent `$0.00`). Training remains **BLOCKED** until Stage 1 PoC diagnostics (`informative_groups > 0`) and explicit budget/grant approval are obtained.

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
  - Initial Modal credit: `$20.00`.
  - Observed cost per full R4 benchmark run (`baseline_5`, 16 targets): `$1.11–$1.38`.
  - Actual metered spend after `cycle8`: `$15.8675` (`$4.1325` remaining; PR #30–#34 spent `$0.00`).

### 4.2 Compute Budget Plan

#### (A) Stage 1 & Stage 2 Micro-PoC on `L4` (`Qwen/Qwen2.5-Coder-1.5B-Instruct`, isolated `aegis-rlvr-grpo-poc`)
- **Stage 1 (`collect-and-diagnose`, `TRAINING_STATUS = BLOCKED`)**: Run `modal_grpo_poc_app.py` via `benchmarks/run_grpo_poc.py --stage collect-and-diagnose` on 2–4 disjoint `train` contracts (`group_size=4`) to verify `informative_groups > 0` and finite `diagnostic_loss` with zero weight updates. Estimated cost: **`< $1` (`~$0.35–$0.80`)** from the remaining `$4.1325` balance.
- **Stage 2 (Micro LoRA GRPO, gated on Stage 1 `informative_groups > 0` + explicit unblock)**: 2–3 LoRA GRPO steps (`r=16, alpha=32`) on `L4` (`bf16`) writing only to `/vol/models/checkpoints_grpo_poc`, followed by 1 optional R4 evaluation (`$1.11–$1.38`) if budget permits.

#### (B) Production GRPO on `H100 80 GB` (Grant Application Scope)
- **Goal**: Scale GRPO LoRA/QLoRA training to a public, reproducible 14B–32B coding/reasoning checkpoint (e.g., `Qwen/Qwen2.5-Coder-14B-Instruct` or `Qwen/Qwen2.5-Coder-32B-Instruct`, or cached `AUDIT_GPU_MODEL` in Modal Volume) to push `baseline_5` recall beyond the `50.00%` (`6/12`) ceiling while preserving `100.00%` precision (`0 FP`) and `100.00%` independent replay.
- **Estimated Compute (Grant Sizing)**:
  - **Model Prefetch & Validation**: 1× cold download of public checkpoint to Modal Volume + `diagnostic_grpo_forward_remote` on `H100`.
  - **Training Rollout Collection**: 40–60 disjoint `train` contracts × `G = 4–8` candidates (160–480 rollouts) at ~33.55s/target baseline inference+sandbox cadence -> ~1.5–4.5 `H100` GPU-hours (plus CPU Foundry replay).
  - **GRPO LoRA/QLoRA Training**: 2–3 epochs over informative groups (`GRPO_GROUP_SIZE=4`, `GRPO_MAX_SEQ_LEN=4096`, `old_logprobs` + `ref_logprobs` pre-pass + backward pass) -> ~2–4 `H100` GPU-hours per training experiment (budgeting 3–5 iterations/ablations = ~6–20 `H100` GPU-hours).
  - **Evaluation Runs**: 5–10 R4 benchmark runs (`$1.11–$1.38` observed each) -> `$5.55–$13.80`.
  - **Recommended Grant Request**: `~15–30 H100 GPU-hours` + `$15–$25` Foundry/CPU & evaluation buffer (total grant target scaled to Modal's current `H100` per-second rate at submission time).

---

## 5. Current Implementation & Preflight Verification Status (`$0.00`)

- **Disjoint Train Split & Collector**: `benchmarks/train_dataset.json`, `benchmarks/targets/solidity_train/`, and `core/train_rollout_collector.py` (10 train contracts validated with zero overlap against the 16 `baseline_5` test targets).
- **Isolated L4 PoC App & Fail-Closed Driver**: `modal_grpo_poc_app.py` (`aegis-rlvr-grpo-poc`) and `benchmarks/run_grpo_poc.py` (requires `AEGIS_APPROVE_GRPO_POC=1` for live calls; `--stage train` blocked client- and server-side while `TRAINING_STATUS = BLOCKED`; `scaledown_window=60`, `min_containers=0`, `buffer_containers=0`).
- **Zero-Cost Preflight Commands**:
  - `python -m benchmarks.run_grpo_poc --dry-run` (validates all 10 train targets locally and prints the L4 execution plan for `$0.00`).
  - `python -m pytest -q tests/test_grpo_poc_driver.py tests/test_grpo_modal_prep.py tests/test_r1_dispatch_contract.py tests/test_r1_bounds_contract.py tests/test_train_rollout_collector.py`
  - `python -m benchmarks.validate_consolidated_closure_evidence --check`
- *Note: No live Modal PoC run (`modal deploy` / `run_grpo_poc.py` without `--dry-run`) has been executed yet; Stage 1 on L4 remains pending explicit budget approval.*
