"""
modal_grpo_poc_app.py
=====================

Isolated fail-closed GRPO PoC Modal application (L4 GPU, 1.5B model).

This module declares its own ``modal.App("aegis-rlvr-grpo-poc")`` and NEVER imports
``modal_app.py``, keeping the production R1 guard and evidence-regeneration trace
completely untouched.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import modal

_REPO_ROOT = str(Path(__file__).resolve().parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from core import r1_bounds as r1
from core.config import config, is_training_blocked
from core.schemas import ExecutionResult, ExploitPayload, TargetProgram
from sandbox.runner import run_payload_in_sandbox, sandbox_image

app = modal.App("aegis-rlvr-grpo-poc")

model_volume = modal.Volume.from_name(config.MODEL_VOLUME_NAME, create_if_missing=True)

poc_gpu_image = (
    modal.Image.debian_slim(python_version="3.10")
    .pip_install(
        "torch",
        "transformers>=4.40.0",
        "accelerate>=0.28.0",
        "peft>=0.14.0",
        "trl>=0.14.0",
        "bitsandbytes>=0.45.0",
        "pydantic>=2.0.0",
    )
    .add_local_python_source("core", "sandbox", copy=True)
    .add_local_file(
        os.path.join(_REPO_ROOT, "benchmarks", "train_dataset.json"),
        "/opt/aegis/benchmarks/train_dataset.json",
        copy=True,
    )
    .add_local_file(
        os.path.join(_REPO_ROOT, "benchmarks", "benchmark_dataset.json"),
        "/opt/aegis/benchmarks/benchmark_dataset.json",
        copy=True,
    )
    .add_local_dir(
        os.path.join(_REPO_ROOT, "benchmarks", "targets", "solidity_train"),
        "/opt/aegis/benchmarks/targets/solidity_train",
        copy=True,
    )
    .add_local_dir(
        os.path.join(_REPO_ROOT, "benchmarks", "targets", "solidity"),
        "/opt/aegis/benchmarks/targets/solidity",
        copy=True,
    )
)


def _resolve_train_dataset_paths() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Return container or local paths for train dataset and test-isolation checks."""
    container_train = "/opt/aegis/benchmarks/train_dataset.json"
    if os.path.exists(container_train):
        return (
            container_train,
            "/opt/aegis/benchmarks/benchmark_dataset.json",
            "/opt/aegis/benchmarks/targets/solidity",
        )
    return None, None, None


@app.function(
    image=sandbox_image,
    timeout=r1.declared_timeout(r1.SANDBOX_CPU_PROFILE),
    block_network=True,
    **r1.SANDBOX_CPU_PROFILE.modal_kwargs(),
)
def poc_verify_train_exploit(target_dict: dict, payload_dict: dict) -> dict:
    """Executes Foundry verification for isolated GRPO PoC train targets."""
    target = TargetProgram(**target_dict)
    payload = ExploitPayload(**payload_dict)
    return run_payload_in_sandbox(target, payload, allow_train_split=True).model_dump()


@app.function(
    gpu=config.GRPO_POC_GPU_TYPE,
    image=poc_gpu_image,
    volumes={"/vol/models": model_volume},
    timeout=1800,
    min_containers=0,
    buffer_containers=0,
    scaledown_window=60,
)
def poc_collect_train_rollouts(
    model_id: str = config.GRPO_BASE_MODEL,
    max_targets: int = 4,
    group_size: int = 4,
    temperatures: Optional[List[float]] = None,
    max_new_tokens: int = 1536,
    run_id: Optional[str] = None,
    trajectory_dir: str = config.GRPO_POC_TRAJECTORY_DIR,
) -> dict:
    """Collects GRPO PoC rollouts on disjoint train targets using L4 GPU."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    from core.prompts import build_exploit_engineer_system_prompt, parse_model_response
    from core.train_rollout_collector import collect_train_rollouts, load_train_targets

    try:
        model_volume.reload()
    except Exception:
        pass

    train_dataset_path, benchmark_dataset_path, test_solidity_dir = _resolve_train_dataset_paths()
    if train_dataset_path is not None:
        targets = load_train_targets(
            train_dataset_path=train_dataset_path,
            benchmark_dataset_path=benchmark_dataset_path,
            test_solidity_dir=test_solidity_dir,
        )
        collect_kwargs: Dict[str, Any] = {
            "benchmark_dataset_path": benchmark_dataset_path,
            "test_solidity_dir": test_solidity_dir,
        }
    else:
        targets = load_train_targets()
        collect_kwargs = {}

    if max_targets is not None and max_targets > 0:
        targets = targets[:max_targets]

    cache_dir = config.MODEL_CACHE_DIR
    tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir=cache_dir)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        cache_dir=cache_dir,
    ).to("cuda")
    model.eval()

    def generator_fn(
        target: TargetProgram,
        prompt_text: str,
        temperature: float,
        cand_idx: int,
    ) -> ExploitPayload:
        messages = [
            {"role": "system", "content": build_exploit_engineer_system_prompt(target.name)},
            {"role": "user", "content": prompt_text},
        ]
        formatted_prompt = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        inputs = tokenizer(formatted_prompt, return_tensors="pt").to("cuda")
        prompt_len = inputs["input_ids"].shape[1]

        gen_kwargs: Dict[str, Any] = {
            "max_new_tokens": max_new_tokens,
            "pad_token_id": tokenizer.pad_token_id,
            "eos_token_id": tokenizer.eos_token_id,
        }
        if temperature > 0:
            gen_kwargs["do_sample"] = True
            gen_kwargs["temperature"] = float(temperature)
            gen_kwargs["top_p"] = 0.95
        else:
            gen_kwargs["do_sample"] = False

        with torch.no_grad():
            outputs = model.generate(
                inputs["input_ids"],
                attention_mask=inputs.get("attention_mask"),
                **gen_kwargs,
            )

        generated_tokens = outputs[0, prompt_len:].tolist()
        raw_text = tokenizer.decode(generated_tokens, skip_special_tokens=True)
        return parse_model_response(
            target=target,
            raw_text=raw_text,
            attempt_idx=cand_idx + 1,
            generated_token_ids=generated_tokens,
            prompt_text=formatted_prompt,
        )

    def verifier_fn(tgt: TargetProgram, pld: ExploitPayload) -> ExecutionResult:
        return ExecutionResult(**poc_verify_train_exploit.remote(tgt.model_dump(), pld.model_dump()))

    result = collect_train_rollouts(
        targets=targets,
        trajectory_dir=trajectory_dir,
        generator_fn=generator_fn,
        verifier_fn=verifier_fn,
        group_size=group_size,
        temperatures=temperatures,
        run_id=run_id,
        **collect_kwargs,
    )

    try:
        model_volume.commit()
    except Exception:
        pass

    return {
        "status": result.get("status", "SUCCESS"),
        "run_id": result.get("run_id"),
        "model_id": model_id,
        "gpu_type": config.GRPO_POC_GPU_TYPE,
        "trajectory_dir": trajectory_dir,
        "persisted_count": result.get("persisted_count", 0),
        "excluded_infra_count": result.get("excluded_infra_count", 0),
        "category_counts": result.get("category_counts", {}),
        "group_spread": result.get("group_spread", {}),
    }


@app.function(
    gpu=config.GRPO_POC_GPU_TYPE,
    image=poc_gpu_image,
    volumes={"/vol/models": model_volume},
    timeout=600,
    min_containers=0,
    buffer_containers=0,
    scaledown_window=60,
)
def poc_diagnostic_grpo_forward(
    model_id: str = config.GRPO_BASE_MODEL,
    batch_group_size: int = 4,
    trajectory_dir: str = config.GRPO_POC_TRAJECTORY_DIR,
) -> dict:
    """Read-only diagnostic GRPO forward pass and group-spread check on L4 GPU."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    from core.grpo_trainer import (
        diagnose_group_spread,
        group_rollouts_by_prompt,
        load_production_trajectories,
        prepare_rollout_tokens,
    )

    try:
        model_volume.reload()
    except Exception:
        pass

    tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir=config.MODEL_CACHE_DIR)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        device_map="cuda",
        cache_dir=config.MODEL_CACHE_DIR,
    )
    model.eval()

    traj_records = load_production_trajectories(trajectory_dir, target_split="train")
    if not traj_records:
        return {
            "status": "NO_PRODUCTION_TRAJECTORIES",
            "message": f"No eligible train trajectories found in {trajectory_dir}.",
            "eligible_count": 0,
            "trajectory_dir": trajectory_dir,
            "optimizer_step_executed": False,
            "weights_updated": False,
            "checkpoints_created": False,
        }

    groups = group_rollouts_by_prompt(traj_records, group_size=batch_group_size)
    spread = diagnose_group_spread(groups)
    if not groups:
        return {
            "status": "NO_VALID_GROUPS",
            "message": "No complete groups formed from eligible trajectories.",
            "eligible_count": len(traj_records),
            "trajectory_dir": trajectory_dir,
            "group_spread": spread,
            "optimizer_step_executed": False,
            "weights_updated": False,
            "checkpoints_created": False,
        }

    test_group = groups[0]
    rollout_tensors = []
    for r in test_group.rollouts:
        c_str = r.full_completion_text or r.exploit_code
        inp_ids, att_mask, comp_mask = prepare_rollout_tokens(
            test_group.prompt,
            c_str,
            tokenizer,
            device="cuda",
            stored_generated_token_ids=r.generated_token_ids,
        )
        rollout_tensors.append((inp_ids, att_mask, comp_mask))

    with torch.no_grad():
        first_inp, first_att, first_comp = rollout_tensors[0]
        outputs = model(first_inp, attention_mask=first_att)
        logits = outputs.logits[:, :-1, :]
        labels = first_inp[:, 1:]
        mask = first_comp[:, 1:]

        log_probs = torch.log_softmax(logits, dim=-1)
        per_token_lp = torch.gather(log_probs, 2, labels.unsqueeze(2)).squeeze(2)
        masked_lp = per_token_lp * mask
        completion_token_count = mask.sum().item()
        diagnostic_loss = -masked_lp.sum().item() / max(1.0, completion_token_count)

    return {
        "status": "SUCCESS",
        "model_id": model_id,
        "gpu_type": config.GRPO_POC_GPU_TYPE,
        "trajectory_dir": trajectory_dir,
        "device": str(model.device),
        "eligible_count": len(traj_records),
        "group_spread": spread,
        "input_shape": list(first_inp.shape),
        "mask_shape": list(first_comp.shape),
        "prompt_tokens": int(first_inp.shape[1] - completion_token_count),
        "completion_tokens": int(completion_token_count),
        "diagnostic_loss": float(diagnostic_loss),
        "optimizer_step_executed": False,
        "weights_updated": False,
        "checkpoints_created": False,
    }


@app.function(
    gpu=config.GRPO_POC_GPU_TYPE,
    image=poc_gpu_image,
    volumes={"/vol/models": model_volume},
    timeout=1800,
    min_containers=0,
    buffer_containers=0,
    scaledown_window=60,
)
def poc_train_grpo(
    model_id: str = config.GRPO_BASE_MODEL,
    num_steps: int = 2,
    learning_rate: float = 5e-6,
    batch_group_size: int = 4,
    trajectory_dir: str = config.GRPO_POC_TRAJECTORY_DIR,
    checkpoint_dir: str = config.GRPO_POC_CHECKPOINT_DIR,
) -> dict:
    """Executes fail-closed LoRA GRPO PoC training on L4 GPU."""
    if is_training_blocked(config):
        raise RuntimeError(
            "FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED. "
            "Direct remote invocation of poc_train_grpo is strictly prohibited by AI Supervisor. "
            "Optimizer step, weight updates, and checkpoint writes are blocked. "
            f"(TRAINING_STATUS={os.environ.get('TRAINING_STATUS', '<unset>')}, "
            f"TRAINING_BLOCKED={os.environ.get('TRAINING_BLOCKED', '<unset>')})"
        )

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    from core.grpo_trainer import (
        group_rollouts_by_prompt,
        load_production_trajectories,
        save_lora_checkpoint,
        setup_lora_model,
        train_grpo_epochs,
    )

    os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

    try:
        model_volume.reload()
    except Exception:
        pass

    trajectories = load_production_trajectories(trajectory_dir, target_split="train")
    groups = group_rollouts_by_prompt(trajectories, group_size=batch_group_size)
    if not groups:
        return {
            "status": "skipped",
            "message": f"No rollout groups found in {trajectory_dir}.",
            "steps_completed": 0,
        }

    tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir=config.MODEL_CACHE_DIR)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    base_model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        cache_dir=config.MODEL_CACHE_DIR,
    ).to("cuda")

    lora_model = setup_lora_model(
        base_model,
        r=config.GRPO_LORA_R,
        lora_alpha=config.GRPO_LORA_ALPHA,
        lora_dropout=config.GRPO_LORA_DROPOUT,
    )

    optimizer = torch.optim.AdamW(
        [p for p in lora_model.parameters() if p.requires_grad],
        lr=learning_rate,
    )

    epochs = max(1, num_steps)
    step_stats = train_grpo_epochs(
        model=lora_model,
        optimizer=optimizer,
        groups=groups,
        tokenizer=tokenizer,
        epochs=epochs,
        device="cuda",
        clip_eps=config.GRPO_CLIP_EPS,
        beta_kl=config.GRPO_BETA_KL,
    )

    save_path = save_lora_checkpoint(lora_model, tokenizer, checkpoint_dir, step=len(step_stats))
    try:
        model_volume.commit()
    except Exception:
        pass

    return {
        "status": "success",
        "model_id": model_id,
        "gpu_type": config.GRPO_POC_GPU_TYPE,
        "trajectory_dir": trajectory_dir,
        "checkpoint_path": save_path,
        "steps_completed": len(step_stats),
        "logs": [s.model_dump() for s in step_stats],
    }
