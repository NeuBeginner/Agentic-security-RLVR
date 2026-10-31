import os
import math
import uuid
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
import torch
import torch.nn.functional as F

from core.config import config
from core.schemas import GRPORollout, GRPOGroup, GRPOTrainingStepStats, RLVRTrajectory, ResultCategory


def compute_prompt_hash(prompt_str: str) -> str:
    """Computes a collision-resistant SHA-256 hash of normalized prompt text."""
    normalized = " ".join(prompt_str.strip().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def make_group_key(
    target_name: str,
    prompt_str: str,
    model_id: str = "default",
    checkpoint_id: str = "base"
) -> str:
    """
    Creates a collision-resistant, version-aware group identity (Round 4).
    Guarantees that prompts differing after character 80 and different model/checkpoint
    configurations are never erroneously merged into the same GRPO advantage group.
    """
    p_hash = compute_prompt_hash(prompt_str)
    return f"{target_name}___{p_hash}___{model_id}___{checkpoint_id}"


# =============================================================================
# 1. MATHEMATICAL GRPO PRIMITIVES (Group Relative Policy Optimization)
# =============================================================================

def compute_group_advantages(rewards: List[float], eps: float = 1e-4) -> List[float]:
    """
    Computes normalized advantages within a group of K rollouts for a single prompt:
        A_i = (r_i - mean(rewards)) / (std(rewards) + eps)
    
    If std(rewards) is essentially zero (e.g. all candidates received identical rewards),
    advantages are returned as 0.0 to prevent amplifying random gradient noise.
    """
    if not rewards:
        return []
    if len(rewards) == 1:
        return [0.0]

    n = len(rewards)
    mean_r = sum(rewards) / n
    variance = sum((r - mean_r) ** 2 for r in rewards) / n
    std_r = math.sqrt(variance)

    if std_r < 1e-6:
        # Uniform performance across the group: no relative advantage
        return [0.0] * n

    return [(r - mean_r) / (std_r + eps) for r in rewards]


def compute_grpo_loss(
    policy_logprobs: torch.Tensor,
    old_logprobs: torch.Tensor,
    advantages: torch.Tensor,
    ref_logprobs: Optional[torch.Tensor] = None,
    completion_mask: Optional[torch.Tensor] = None,
    clip_eps: float = 0.2,
    beta_kl: float = 0.04
) -> Tuple[torch.Tensor, Dict[str, float]]:
    """
    Computes GRPO policy gradient loss with PPO clipping and reference model KL penalty.
    
    Formula:
        ratio = exp(policy_logprobs - old_logprobs)
        surr1 = ratio * advantage
        surr2 = clip(ratio, 1 - eps, 1 + eps) * advantage
        policy_loss = -min(surr1, surr2)
        kl = exp(ref_logprobs - policy_logprobs) - (ref_logprobs - policy_logprobs) - 1
        total_loss = mean(policy_loss + beta_kl * kl)
    
    Args:
        policy_logprobs: Log-probabilities from active policy [batch_size, seq_len]
        old_logprobs: Log-probabilities from rollout generation policy [batch_size, seq_len]
        advantages: Group-normalized advantages [batch_size]
        ref_logprobs: Reference model logprobs for KL constraint [batch_size, seq_len]
        completion_mask: Binary mask [batch_size, seq_len] indicating completion tokens
        clip_eps: PPO clipping epsilon (default: 0.2)
        beta_kl: KL penalty weight (default: 0.04)
        
    Returns:
        (total_loss, metrics_dict)
    """
    # Align advantages tensor to [batch_size, 1] for broadcasting across sequence length
    if advantages.dim() == 1:
        adv = advantages.unsqueeze(-1)
    else:
        adv = advantages

    # Importance sampling ratio: pi_theta / pi_old
    log_ratio = policy_logprobs - old_logprobs
    ratio = torch.exp(log_ratio)

    # Clipped surrogate objective
    surr1 = ratio * adv
    surr2 = torch.clamp(ratio, 1.0 - clip_eps, 1.0 + clip_eps) * adv
    policy_loss = -torch.min(surr1, surr2)

    # KL Divergence penalty against reference model (Schulman k3 estimator)
    if ref_logprobs is not None:
        log_ref_ratio = ref_logprobs - policy_logprobs
        kl_div = torch.exp(log_ref_ratio) - log_ref_ratio - 1.0
    else:
        kl_div = torch.exp(-log_ratio) + log_ratio - 1.0

    total_token_loss = policy_loss + beta_kl * kl_div

    # Apply completion mask so we only compute loss on generated tokens (not prompt tokens)
    if completion_mask is not None:
        token_count = completion_mask.sum().clamp(min=1.0)
        final_loss = (total_token_loss * completion_mask).sum() / token_count
        mean_kl = (kl_div * completion_mask).sum() / token_count
        mean_ratio = (ratio * completion_mask).sum() / token_count
    else:
        final_loss = total_token_loss.mean()
        mean_kl = kl_div.mean()
        mean_ratio = ratio.mean()

    # Calculate clipping fraction for diagnostics
    clipped = (ratio < (1.0 - clip_eps)) | (ratio > (1.0 + clip_eps))
    clip_fraction = (
        (clipped.float() * completion_mask).sum().item() / max(1.0, completion_mask.sum().item())
        if completion_mask is not None
        else clipped.float().mean().item()
    )

    metrics = {
        "loss": final_loss.item(),
        "kl": mean_kl.item(),
        "mean_ratio": mean_ratio.item(),
        "clip_fraction": clip_fraction,
        "mean_advantage": adv.mean().item()
    }
    return final_loss, metrics


# =============================================================================
# 2. EXACT TOKEN BOUNDARY ALIGNMENT & LOGPROBS (ROUND 4)
# =============================================================================

def prepare_rollout_tokens(
    prompt_str: str,
    completion_str: str,
    tokenizer: Any,
    device: str = "cuda",
    max_seq_len: int = 1536,
    stored_generated_token_ids: Optional[List[int]] = None
) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """
    Prepares input_ids, attention_mask, and completion_mask with verified boundary integrity.
    
    If stored_generated_token_ids are provided from generation context, uses them directly
    to prevent BPE junction tokenization artifacts.
    Otherwise, computes boundary by tokenizing prompt and completion with explicit EOS handling.
    
    Completion mask is 0.0 on prompt tokens and 1.0 on completion tokens.
    Empty completions yield an all-zero completion_mask.
    """
    # Guard against duplicate BOS or special tokens if chat template is already applied
    has_chat_template = False
    if "<|im_start|>" in prompt_str:
        has_chat_template = True
    elif getattr(tokenizer, "bos_token", None) and prompt_str.startswith(tokenizer.bos_token):
        has_chat_template = True

    add_spec = not has_chat_template
    prompt_ids = tokenizer.encode(prompt_str, add_special_tokens=add_spec)

    if stored_generated_token_ids is not None:
        completion_ids = list(stored_generated_token_ids)
    else:
        if not completion_str or not completion_str.strip():
            completion_ids = []
        else:
            completion_ids = tokenizer.encode(completion_str, add_special_tokens=False)

    if tokenizer.eos_token_id is not None:
        if completion_ids and completion_ids[-1] != tokenizer.eos_token_id:
            completion_ids.append(tokenizer.eos_token_id)

    total_len = len(prompt_ids) + len(completion_ids)
    if total_len > max_seq_len:
        excess = total_len - max_seq_len
        if excess < len(prompt_ids):
            # Truncate prompt from the left (keep the latest context)
            prompt_ids = prompt_ids[excess:]
        else:
            completion_ids = completion_ids[:max(0, max_seq_len - 1)]
            prompt_ids = prompt_ids[:1]

    full_ids = prompt_ids + completion_ids
    input_ids = torch.tensor([full_ids], dtype=torch.long, device=device)
    attention_mask = torch.ones_like(input_ids)

    plen = len(prompt_ids)
    completion_mask = torch.zeros_like(input_ids, dtype=torch.float32)
    if completion_ids:
        completion_mask[:, plen:] = 1.0

    return input_ids, attention_mask, completion_mask


def get_token_logprobs(
    model: torch.nn.Module,
    input_ids: torch.Tensor,
    attention_mask: torch.Tensor
) -> torch.Tensor:
    """Computes next-token log-probabilities under the provided model."""
    outputs = model(input_ids=input_ids, attention_mask=attention_mask)
    shift_logits = outputs.logits[:, :-1, :].contiguous()
    shift_labels = input_ids[:, 1:].contiguous()
    log_probs = F.log_softmax(shift_logits, dim=-1)
    return torch.gather(log_probs, 2, shift_labels.unsqueeze(-1)).squeeze(-1)


def compute_rollout_baselines(
    model: torch.nn.Module,
    input_ids: torch.Tensor,
    attention_mask: torch.Tensor
) -> Tuple[torch.Tensor, torch.Tensor]:
    """
    Computes both old_logprobs and true reference ref_logprobs in torch.no_grad().
    Uses PEFT's disable_adapter() to query the frozen base model for reference KL.
    Zero additional VRAM required!
    """
    with torch.no_grad():
        # 1. Old logprobs under policy before gradient updates
        old_logprobs = get_token_logprobs(model, input_ids, attention_mask)

        # 2. Reference logprobs under frozen base model
        if hasattr(model, "disable_adapter"):
            with model.disable_adapter():
                ref_logprobs = get_token_logprobs(model, input_ids, attention_mask)
        else:
            ref_logprobs = old_logprobs.clone()

    return old_logprobs, ref_logprobs


# =============================================================================
# 3. DATASET BATCHING & GROUPING (ROUND 4)
# =============================================================================

def group_rollouts_by_prompt(
    rollouts_data: List[Dict[str, Any]],
    group_size: Optional[int] = None
) -> List[GRPOGroup]:
    """
    Groups accumulated trajectory records into GRPOGroup structures and calculates
    group-relative advantages for each candidate.
    
    CRITICAL POLICIES (ROUND 4):
    1. Collision-Resistant Identity: Groups by target + SHA-256 prompt hash + model/checkpoint version.
       Prompts differing after character 80 and different checkpoints are NEVER mixed.
    2. INFRA_ERROR Exclusion: Trajectories with INFRA_ERROR are strictly filtered out before
       bucketing, ensuring environment failures never affect group rewards, means, standard deviations,
       or advantage calculations.
    """
    effective_group_size = group_size or config.GRPO_GROUP_SIZE

    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for r in rollouts_data:
        # Strictly exclude infrastructure failures from GRPO policy training
        cat = str(r.get("category", "")).upper()
        if "INFRA_ERROR" in cat:
            continue

        target_name = r.get("target_name", "target")
        prompt_used = r.get("prompt_used", "")
        model_id = r.get("model_id", "default")
        checkpoint_id = r.get("checkpoint_id", "base")

        key = make_group_key(target_name, prompt_used, model_id, checkpoint_id)
        if key not in buckets:
            buckets[key] = []
        buckets[key].append(r)

    groups: List[GRPOGroup] = []

    for key, items in buckets.items():
        for chunk_idx in range(0, len(items), effective_group_size):
            chunk = items[chunk_idx : chunk_idx + effective_group_size]
            if len(chunk) < 2:
                continue

            rewards = [float(item.get("reward", 0.0)) for item in chunk]
            advantages = compute_group_advantages(rewards)

            mean_r = sum(rewards) / len(rewards)
            var_r = sum((r - mean_r) ** 2 for r in rewards) / len(rewards)
            std_r = math.sqrt(var_r)

            first_item = chunk[0]
            target_name = first_item.get("target_name", "Vault")
            prompt_str = first_item.get("prompt_used", "")
            model_id = first_item.get("model_id", "default")
            checkpoint_id = first_item.get("checkpoint_id", "base")
            p_hash = compute_prompt_hash(prompt_str)

            rollouts: List[GRPORollout] = []
            for item, adv in zip(chunk, advantages):
                hyp_dict = item.get("hypothesis", {})
                if isinstance(hyp_dict, dict):
                    from core.schemas import AttackHypothesis
                    hypothesis = AttackHypothesis(
                        vulnerability_type=hyp_dict.get("vulnerability_type", "Unknown"),
                        reasoning_trace=hyp_dict.get("reasoning_trace", ""),
                        attack_vector=hyp_dict.get("attack_vector", "")
                    )
                else:
                    hypothesis = hyp_dict

                cat_raw = item.get("category", ResultCategory.RUNTIME_REVERT)
                if isinstance(cat_raw, ResultCategory):
                    cat_enum = cat_raw
                elif isinstance(cat_raw, str):
                    cat_clean = cat_raw.replace("ResultCategory.", "")
                    try:
                        cat_enum = ResultCategory(cat_clean)
                    except ValueError:
                        cat_enum = ResultCategory.RUNTIME_REVERT
                else:
                    cat_enum = ResultCategory.RUNTIME_REVERT

                rollouts.append(GRPORollout(
                    candidate_id=item.get("candidate_id") or item.get("trajectory_id", str(uuid.uuid4())),
                    run_id=item.get("run_id", "run-default"),
                    model_id=model_id,
                    checkpoint_id=checkpoint_id,
                    prompt_hash=p_hash,
                    hypothesis=hypothesis,
                    full_completion_text=item.get("full_completion_text") or item.get("raw_model_response") or item.get("generated_exploit", ""),
                    exploit_code=item.get("generated_exploit", ""),
                    reward=float(item.get("reward", 0.0)),
                    category=cat_enum,
                    is_verified=bool(item.get("is_verified", False)),
                    reproduced=bool(item.get("reproduced", False)),
                    feedback=str(item.get("feedback_trace", "")),
                    advantage=adv,
                    generated_token_ids=item.get("generated_token_ids")
                ))

            groups.append(GRPOGroup(
                group_id=str(uuid.uuid4()),
                target_name=target_name,
                prompt=prompt_str,
                prompt_hash=p_hash,
                model_id=model_id,
                checkpoint_id=checkpoint_id,
                system_prompt=first_item.get("system_prompt", "You are an autonomous Web3 smart contract security auditor."),
                rollouts=rollouts,
                mean_reward=mean_r,
                std_reward=std_r
            ))

    return groups


def load_trajectories_from_directory(
    trajectory_dir: str,
    target_split: str = "train",
    target_partition: str = "production",
    require_exact_tokens: bool = False
) -> List[Dict[str, Any]]:
    """
    Loads, schema-validates, and deduplicates JSON trajectory files from the persistent volume.
    
    CRITICAL POLICIES (ROUND 4 & ROUND 5.2):
    1. Schema & Invariant Validation: Validates records using RLVRTrajectory. Inconsistent or unfinalized records are rejected.
    2. Strict Production Allowlist (Round 5.2 Blocker 3):
       - Only records with dataset_partition == target_partition ('production')
       - is_synthetic MUST be False
       - trainable MUST be True
       - category MUST NOT be INFRA_ERROR
       - dataset_split MUST match target_split
    3. Fail-Closed on Missing / Inconsistent Provenance:
       - Records with unknown partition or synthetic origin are strictly excluded from production training.
    4. Token Provenance Integrity (Round 5.2 Blocker 1 & 2):
       - If require_exact_tokens is True, requires token_provenance == 'model_generate' and valid generated_token_ids.
       - External API records marked 'external_text_only' cannot enter exact-lineage GRPO training.
    5. Deduplication: Tracks seen candidate_id and trajectory_id to guarantee no duplicate ingestion.
    """
    records = []
    if not os.path.exists(trajectory_dir):
        return records

    seen_trajectory_ids = set()
    seen_candidate_ids = set()

    for fname in sorted(os.listdir(trajectory_dir)):
        if fname.endswith(".json") and fname.startswith("traj_"):
            fpath = os.path.join(trajectory_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Fail-closed check for missing provenance fields in raw data
                if "dataset_partition" not in data or "is_synthetic" not in data:
                    continue

                # 1. Schema and Invariant Validation
                traj = RLVRTrajectory(**data)

                # 2. Must be finalized before entering GRPO
                if not traj.is_finalized:
                    continue

                # 3. Strict Partition Allowlist & Synthetic Isolation (Round 5.2)
                if traj.dataset_partition != target_partition:
                    continue
                if traj.is_synthetic is True:
                    continue
                if traj.trainable is not True:
                    continue

                # 4. Dataset split isolation (train vs val/holdout)
                if traj.dataset_split != target_split:
                    continue

                # 5. Strictly exclude infrastructure errors
                if traj.category == ResultCategory.INFRA_ERROR:
                    continue

                # 6. Exact Token Lineage Check (Round 5.2 Blocker 1)
                if require_exact_tokens:
                    if traj.token_provenance != "model_generate":
                        continue
                    if not traj.generated_token_ids or len(traj.generated_token_ids) == 0:
                        continue

                # 7. Deduplication check
                if traj.trajectory_id in seen_trajectory_ids:
                    continue
                if traj.candidate_id and traj.candidate_id in seen_candidate_ids:
                    continue

                seen_trajectory_ids.add(traj.trajectory_id)
                if traj.candidate_id:
                    seen_candidate_ids.add(traj.candidate_id)

                records.append(traj.model_dump())
            except Exception as e:
                # Malformed or inconsistent trajectory rejected (fail closed)
                pass

    return records


def audit_trajectory_storage(trajectory_dir: str) -> Dict[str, Any]:
    """
    Performs a strict read-only audit of existing trajectories in the specified directory (Round 5.2).
    Does NOT alter, migrate, or delete any existing trajectory files.
    """
    report: Dict[str, Any] = {
        "trajectory_dir": trajectory_dir,
        "total_files": 0,
        "valid_schema_count": 0,
        "malformed_count": 0,
        "by_partition": {"production": 0, "synthetic_control": 0, "test": 0, "missing_or_other": 0},
        "by_synthetic": {"synthetic": 0, "non_synthetic": 0},
        "by_trainable": {"trainable": 0, "non_trainable": 0},
        "by_token_provenance": {"model_generate": 0, "external_text_only": 0, "synthetic": 0, "missing": 0},
        "by_category": {},
        "production_eligible_for_grpo": 0,
        "audit_timestamp": time.time() if "time" in globals() else 0.0
    }
    import time
    report["audit_timestamp"] = time.time()

    if not os.path.exists(trajectory_dir):
        return report

    for fname in sorted(os.listdir(trajectory_dir)):
        if fname.endswith(".json") and fname.startswith("traj_"):
            report["total_files"] += 1
            fpath = os.path.join(trajectory_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)

                part = raw_data.get("dataset_partition", "missing_or_other")
                if part in report["by_partition"]:
                    report["by_partition"][part] += 1
                else:
                    report["by_partition"]["missing_or_other"] += 1

                is_syn = raw_data.get("is_synthetic", False)
                if is_syn:
                    report["by_synthetic"]["synthetic"] += 1
                else:
                    report["by_synthetic"]["non_synthetic"] += 1

                is_tr = raw_data.get("trainable", True)
                if is_tr:
                    report["by_trainable"]["trainable"] += 1
                else:
                    report["by_trainable"]["non_trainable"] += 1

                tok_prov = raw_data.get("token_provenance", "missing")
                if tok_prov in report["by_token_provenance"]:
                    report["by_token_provenance"][tok_prov] += 1
                else:
                    report["by_token_provenance"]["missing"] += 1

                cat_str = str(raw_data.get("category", "UNKNOWN"))
                report["by_category"][cat_str] = report["by_category"].get(cat_str, 0) + 1

                # Validate with schema
                traj = RLVRTrajectory(**raw_data)
                report["valid_schema_count"] += 1

                # Check if would pass production loader
                if (traj.dataset_partition == "production" and 
                    not traj.is_synthetic and 
                    traj.trainable and 
                    traj.is_finalized and 
                    traj.category != ResultCategory.INFRA_ERROR):
                    report["production_eligible_for_grpo"] += 1

            except Exception as e:
                report["malformed_count"] += 1

    return report


# =============================================================================
# 4. LORA / PEFT ADAPTER CONFIGURATION
# =============================================================================

def setup_lora_model(
    base_model: torch.nn.Module,
    r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
    target_modules: Optional[Tuple[str, ...]] = None
):
    """
    Wraps the causal language model with LoRA adapters using PEFT.
    Only LoRA parameters are trainable, preserving base model reasoning capabilities.
    Enables gradient checkpointing to drastically cut VRAM requirements.
    """
    from peft import LoraConfig, get_peft_model, TaskType

    if hasattr(base_model, "gradient_checkpointing_enable"):
        try:
            base_model.gradient_checkpointing_enable()
            print("[✓] Gradient checkpointing enabled on base model.")
        except Exception:
            pass

    if hasattr(base_model, "enable_input_require_grads"):
        try:
            base_model.enable_input_require_grads()
        except Exception:
            pass

    if target_modules is None:
        target_modules = config.GRPO_TARGET_MODULES

    peft_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        target_modules=list(target_modules),
        bias="none"
    )

    lora_model = get_peft_model(base_model, peft_config)
    trainable_params, all_params = lora_model.get_nb_trainable_parameters()
    print(f"[*] LoRA Model Initialized: {trainable_params:,} trainable / {all_params:,} total parameters ({100 * trainable_params / all_params:.2f}%)")
    return lora_model


# =============================================================================
# 5. MULTI-EPOCH GRPO TRAINING LOOP OVER GROUPS
# =============================================================================

def train_grpo_epochs(
    model: torch.nn.Module,
    optimizer: torch.optim.Optimizer,
    groups: List[GRPOGroup],
    tokenizer: Any,
    epochs: int = 2,
    device: str = "cuda",
    clip_eps: float = 0.2,
    beta_kl: float = 0.04,
    max_grad_norm: float = 1.0,
    max_seq_len: int = 1536
) -> List[GRPOTrainingStepStats]:
    """
    Executes multiple GRPO optimization epochs over all rollout groups:
    1. Pre-computes and freezes old_logprobs and ref_logprobs for each candidate in torch.no_grad().
    2. Runs training epochs where policy logprobs dynamically diverge from old_logprobs,
       activating PPO clipping and reference KL regularization.
    3. Accumulates gradients with micro-batching across each candidate in the group.
    """
    all_step_stats: List[GRPOTrainingStepStats] = []
    if not groups:
        return all_step_stats

    # Step A: Pre-tokenize and calculate old_logprobs + ref_logprobs for each candidate
    print(f"[*] Pre-computing old_logprobs and frozen reference ref_logprobs across {len(groups)} group(s)...")
    model.eval()

    prepared_groups = []
    for g_idx, group in enumerate(groups, 1):
        group_items = []
        for r_item in group.rollouts:
            training_completion = r_item.full_completion_text or r_item.exploit_code
            input_ids, attention_mask, completion_mask = prepare_rollout_tokens(
                prompt_str=group.prompt,
                completion_str=training_completion,
                tokenizer=tokenizer,
                device=device,
                max_seq_len=max_seq_len,
                stored_generated_token_ids=r_item.generated_token_ids
            )
            # Fail-closed invariant checks (Round 5.2 Blocker 2)
            if input_ids.shape != attention_mask.shape or input_ids.shape != completion_mask.shape:
                raise ValueError(
                    f"Shape mismatch in GRPO tensors: input_ids {input_ids.shape}, "
                    f"attention_mask {attention_mask.shape}, completion_mask {completion_mask.shape}"
                )
            if completion_mask.sum().item() == 0:
                raise ValueError(
                    f"Fail-closed: completion_mask has 0 active tokens for rollout '{r_item.candidate_id}'. "
                    "Cannot optimize policy without completion tokens."
                )

            old_logprobs, ref_logprobs = compute_rollout_baselines(model, input_ids, attention_mask)
            shift_mask = completion_mask[:, 1:].contiguous()
            group_items.append({
                "input_ids": input_ids,
                "attention_mask": attention_mask,
                "shift_mask": shift_mask,
                "old_logprobs": old_logprobs,
                "ref_logprobs": ref_logprobs,
                "advantage": r_item.advantage,
                "reward": r_item.reward
            })
        prepared_groups.append((group, group_items))

    # Step B: Optimization epochs
    global_step = 0
    model.train()

    for epoch in range(1, epochs + 1):
        print(f"\n[*] Starting GRPO Training Epoch {epoch}/{epochs}...")
        for g_idx, (group, items) in enumerate(prepared_groups, 1):
            optimizer.zero_grad()
            num_rollouts = len(items)

            epoch_loss = 0.0
            epoch_kl = 0.0
            epoch_ratio = 0.0
            epoch_clip = 0.0

            for item in items:
                input_ids = item["input_ids"]
                attention_mask = item["attention_mask"]
                shift_mask = item["shift_mask"]
                old_logprobs = item["old_logprobs"]
                ref_logprobs = item["ref_logprobs"]
                adv_val = item["advantage"]

                # Active policy forward pass
                policy_logprobs = get_token_logprobs(model, input_ids, attention_mask)
                adv_tensor = torch.tensor([adv_val], dtype=torch.float32, device=device)

                sub_loss, sub_metrics = compute_grpo_loss(
                    policy_logprobs=policy_logprobs,
                    old_logprobs=old_logprobs,
                    advantages=adv_tensor,
                    ref_logprobs=ref_logprobs,
                    completion_mask=shift_mask,
                    clip_eps=clip_eps,
                    beta_kl=beta_kl
                )

                # Gradient accumulation across group candidates
                scaled_loss = sub_loss / num_rollouts
                scaled_loss.backward()

                epoch_loss += sub_metrics["loss"] / num_rollouts
                epoch_kl += sub_metrics["kl"] / num_rollouts
                epoch_ratio += sub_metrics["mean_ratio"] / num_rollouts
                epoch_clip += sub_metrics["clip_fraction"] / num_rollouts

            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=max_grad_norm)
            optimizer.step()
            global_step += 1

            current_lr = optimizer.param_groups[0]["lr"] if optimizer.param_groups else 0.0

            stats = GRPOTrainingStepStats(
                step=global_step,
                loss=epoch_loss,
                mean_reward=group.mean_reward,
                mean_advantage=0.0,
                kl_divergence=epoch_kl,
                learning_rate=current_lr
            )
            all_step_stats.append(stats)
            print(f"    [Epoch {epoch}/{epochs} | Group {g_idx}/{len(prepared_groups)}] Loss: {epoch_loss:.4f} | Ratio: {epoch_ratio:.4f} | KL: {epoch_kl:.6f} | Clip: {epoch_clip * 100:.1f}%")

            if torch.cuda.is_available():
                torch.cuda.empty_cache()

    return all_step_stats


def save_lora_checkpoint(model: Any, tokenizer: Any, output_dir: str, step: int = 1) -> str:
    """Saves LoRA adapter weights, tokenizer, and config to output directory."""
    save_path = os.path.join(output_dir, f"checkpoint-step-{step}")
    os.makedirs(save_path, exist_ok=True)

    if hasattr(model, "save_pretrained"):
        model.save_pretrained(save_path)
    if hasattr(tokenizer, "save_pretrained"):
        tokenizer.save_pretrained(save_path)

    print(f"[✓] LoRA Checkpoint committed to: {save_path}")
    return save_path


# =============================================================================
# 6. HUGGING FACE TRL INTEGRATION (Optional high-level GRPOTrainer wrapper)
# =============================================================================

def create_trl_grpo_config(
    output_dir: str = "/vol/models/checkpoints",
    learning_rate: float = 5e-6,
    num_train_epochs: int = 1,
    per_device_train_batch_size: int = 1,
    gradient_accumulation_steps: int = 4
):
    try:
        from trl import GRPOConfig
        return GRPOConfig(
            output_dir=output_dir,
            learning_rate=learning_rate,
            num_train_epochs=num_train_epochs,
            per_device_train_batch_size=per_device_train_batch_size,
            gradient_accumulation_steps=gradient_accumulation_steps,
            logging_steps=1,
            save_strategy="steps",
            save_steps=10
        )
    except ImportError:
        return None
