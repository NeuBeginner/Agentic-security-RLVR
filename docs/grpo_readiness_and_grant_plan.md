# GRPO Readiness Audit & Compute Grant Plan

> **Audit Scope & Status**: `$0.00` Modal spend (read-only code audit + local verification only).  
> **Training Gate**: `TRAINING_STATUS = BLOCKED` (fail-closed in `core/config.py`, `core/grpo_trainer.py`, and `modal_app.py`).  
> **Reference Benchmark Artifact**: `benchmarks/artifacts/run_1795027271_8c19acf` (`cycle8`, `baseline_5`).

---

## 1. Executive Summary

The offline GRPO trainer (`core/grpo_trainer.py`), trajectory schema (`core/evaluator.py`, `core/schemas.py`), and evidence-scoped Reward v2.0.0 (`core/config.py`, `core/reward_shaping.py`) are **structurally compatible** with the inference and sandbox payloads produced in `cycle8` (`run_1795027271_8c19acf`).

However, **real GRPO training cannot be executed yet** due to three concrete technical blockers and a depleted initial credit balance (`$4.13` remaining of `$20.00`):

1. **Data Isolation & Degenerate Groups (`benchmarks/adapters.py`)**: Only `is_verified` benchmark runs are persisted, and they are hardcoded to `dataset_split="test"`, `dataset_partition="test"`, `trainable=False`. No `train` contract split or multi-candidate (`G >= 4`) rollout collection with reward variance exists.
2. **GPU Tier & Base Model Accessibility (`core/config.py`, `modal_app.py`)**: `train_grpo_remote` and `diagnostic_grpo_forward_remote` are bound to `DEV_GPU_TYPE = "T4"` (16 GB VRAM), `gpu_image` lacks `bitsandbytes` for QLoRA, and `AUDIT_GPU_MODEL` (`qtum/Qwen3-Coder-30B-A3B-Audit`) returns `401` on Hugging Face (only cached in the Modal Volume).
3. **Fail-Closed Training Gate & Budget (`core/config.py`, `modal_app.py`)**: `TRAINING_STATUS=BLOCKED` prevents any `optimizer.step()`, and the remaining `$4.13` Modal balance is insufficient for production 27B–35B GRPO training + post-training R4 evaluation.

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

## 3. Technical Blockers Before GRPO Execution

### Blocker 1: `train` / `test` Data Isolation & Non-Degenerate Groups (`informative_groups`)

- **Current Code Behavior**:
  - `benchmarks/adapters.py:L2724-L2734`: Trajectory persistence runs **only** inside `if is_verified:` (6/16 targets in `cycle8`; the other 10 targets have `persistence_status="not_eligible"`). Even for those 6, `create_trajectory_record` is called with `dataset_split="test"`, `dataset_partition="test"`, `is_synthetic=False`, `trainable=False`.
  - `core/grpo_trainer.py:L737-L742`: `evaluate_trajectory_eligibility` requires `dataset_partition == "production"`, `trainable is True`, and `dataset_split == "train"`.
  - `core/grpo_trainer.py:L529-L533`: `group_rollouts_by_prompt` requires `len(chunk) >= 2` (default `GRPO_GROUP_SIZE = 4` in `core/config.py:L106`).
  - `core/grpo_trainer.py:L432-L478` & `L1124-L1133`: `diagnose_group_spread` and `train_grpo_epochs` fail closed (`ValueError`) when `informative_groups == 0` (i.e., `std_reward < 1e-6` across every group, yielding zero policy gradient).
  - `modal_app.py:L1183-L1194`: `train_grpo_remote` loads `target_split="train"` and exits early if no groups with `>= 2` candidates exist.
- **Required Fix**:
  1. Introduce a dedicated `train` split of Solidity contracts **disjoint from the 16 benchmark targets** in `baseline_5` (preventing train/test leakage).
  2. Persist **both** successful (`EXPLOIT_CONFIRMED`, `+1.0`) and failed rollouts (`SAFE_RUN` `-0.10`, `RUNTIME_REVERT` `-0.25`, `COMPILATION_ERROR` `-0.50`, `GENERATION_FORMAT_ERROR` `-0.35`, excluding `INFRA_ERROR`) during training rollout collection, with `G >= 4` candidates per prompt (`temperature > 0`) so `diagnose_group_spread` yields `informative_groups > 0`.
  3. Tag training rollouts with `dataset_partition="production"`, `dataset_split="train"`, `trainable=True`, `is_synthetic=False`, and `token_provenance="model_generate"` with non-empty `generated_token_ids`.

### Blocker 2: GPU Hardware (`T4` vs `H100`) & Base Model Availability (`401`)

- **Current Code Behavior**:
  - `core/config.py:L19-L24`:
    - `AUDIT_GPU_MODEL = "qtum/Qwen3-Coder-30B-A3B-Audit"`, `AUDIT_GPU_TYPE = "H100"` (80 GB VRAM; ~61 GB cached weights noted in `modal_app.py:L97`).
    - `DEV_GPU_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"`, `DEV_GPU_TYPE = "T4"` (16 GB VRAM).
  - `modal_app.py:L1138-L1143`: `train_grpo_remote` is decorated with `gpu=config.DEV_GPU_TYPE` (`"T4"`), which only fits `Qwen2.5-Coder-1.5B-Instruct`, not 27B–35B models.
  - `modal_app.py:L1035-L1073`: `diagnostic_grpo_forward_remote` is also decorated with `gpu=config.DEV_GPU_TYPE` (`"T4"`), yet loads `torch_dtype=torch.bfloat16` (`L1071`, unsupported natively on T4 Turing) and can be invoked with `config.AUDIT_GPU_MODEL` (`L1679`, 30B -> OOM on 16 GB T4).
  - `modal_app.py:L73-L85`: `gpu_image` installs `transformers>=4.40.0`, `accelerate>=0.28.0`, `peft>=0.14.0`, `trl>=0.14.0`, and **does not include `bitsandbytes`** (needed for 4-bit QLoRA).
  - **Hugging Face `401` on `qtum/Qwen3-Coder-30B-A3B-Audit`**: The repository is inaccessible/private on Hugging Face (`401`), surviving only in the Modal Volume cache (`/vol/models/huggingface`).
- **Required Fix**:
  1. Split PoC vs. Production training configs:
     - **PoC (1.5B)**: `Qwen/Qwen2.5-Coder-1.5B-Instruct` on `T4` (`fp16`) or `A10G` (`bf16`).
     - **Production (27B–35B)**: Upgrade `train_grpo_remote` and `diagnostic_grpo_forward_remote` to `H100` (80 GB VRAM, `bf16`) with gradient checkpointing (`setup_lora_model` in `core/grpo_trainer.py:L1047-L1052`) and optional `bitsandbytes` QLoRA if optimizer/activation memory at `GRPO_MAX_SEQ_LEN=4096` exceeds 80 GB.
  2. Migrate `AUDIT_GPU_MODEL` to an open, publicly reproducible Hugging Face checkpoint (e.g., `Qwen/Qwen3.8-27B` or `Qwen/Qwen3.6-35B-A3B`) and pin the compatible `transformers` version in `modal_app.py:gpu_image`.

### Blocker 3: Fail-Closed Security Gate (`TRAINING_STATUS = BLOCKED`)

- `core/config.py:L98, L139-L140`, `core/grpo_trainer.py:L1106-L1112`, and `modal_app.py:L1164-L1171` enforce `is_training_blocked(config)` at call time. Both `TRAINING_STATUS` (must be `UNBLOCKED`/`ENABLED`/`RUNNING`) and `TRAINING_BLOCKED` (must be explicit false) are required before `train_grpo_epochs` or `train_grpo_remote` can execute. This gate remains **BLOCKED** until budget and Blocker 1/2 are resolved.

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
  - Remaining Modal credit: `$4.13`.

### 4.2 Compute Budget Plan

#### (A) PoC GRPO on `1.5B` (`Qwen2.5-Coder-1.5B-Instruct` on `T4` / `A10G`)
- **Goal**: End-to-end validation of non-degenerate `train` rollout collection (`G = 4`), `diagnostic_grpo_forward_remote`, and 2–3 epochs of LoRA GRPO (`r=16, alpha=32`) before spending H100 grant funds.
- **Estimated Compute**:
  - Rollout collection (e.g., 15–25 `train` contracts × `G = 4` candidates = 60–100 rollouts + Foundry verification): ~0.3–0.6 T4/A10G GPU-hours + sandbox CPU time.
  - GRPO training (`train_grpo_remote`, 2–3 epochs, `GRPO_MAX_SEQ_LEN=4096`): ~0.2–0.4 T4/A10G GPU-hours.
  - Post-PoC R4 evaluation (1–2 runs at `$1.11–$1.38`/run): `$1.11–$2.76`.
- **Feasibility**: Fits within the remaining `$4.13` Modal credit if scoped strictly to 1.5B PoC + 1 R4 check, leaving minimal margin for retries.

#### (B) Production GRPO on `27B–35B` (`Qwen/Qwen3.8-27B` or `Qwen/Qwen3.6-35B-A3B` on `H100 80 GB`)
- **Goal**: Improve `baseline_5` recall beyond the `50.00%` (`6/12`) ceiling while preserving `100.00%` precision (`0 FP`) and `100.00%` independent replay.
- **Estimated Compute (Grant Sizing)**:
  - **Model Prefetch & Validation**: 1× cold download of open 27B–35B checkpoint to Modal Volume + `diagnostic_grpo_forward_remote` on `H100`.
  - **Training Rollout Collection**: 40–60 disjoint `train` contracts × `G = 4–8` candidates (160–480 rollouts) at ~33.55s/target baseline inference+sandbox cadence -> ~1.5–4.5 `H100` GPU-hours (plus CPU Foundry replay).
  - **GRPO LoRA/QLoRA Training**: 2–3 epochs over informative groups (`GRPO_GROUP_SIZE=4`, `GRPO_MAX_SEQ_LEN=4096`, `old_logprobs` + `ref_logprobs` pre-pass + backward pass) -> ~2–4 `H100` GPU-hours per training experiment (budgeting 3–5 iterations/ablations = ~6–20 `H100` GPU-hours).
  - **Evaluation Runs**: 5–10 R4 benchmark runs (`$1.11–$1.38` observed each) -> `$5.55–$13.80`.
  - **Recommended Grant Request**: `~15–30 H100 GPU-hours` + `$15–$25` Foundry/CPU & evaluation buffer (total grant target scaled to Modal's current `H100` per-second rate at submission time).

---

## 5. Local Verification Results (`$0.00`)

Executed locally on `docs/grpo-readiness-audit`:

1. `python -m pytest -q tests/test_grpo.py tests/test_grpo_integrity.py tests/test_round5_2_data_isolation.py tests/test_round5_4_security_gates.py tests/test_trajectory_integrity.py` -> **27 passed** (`1.90s`).
2. `python -m benchmarks.validate_consolidated_closure_evidence --check` -> **21/21 PASSED**.
