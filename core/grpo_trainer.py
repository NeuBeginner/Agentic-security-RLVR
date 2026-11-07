import os
import math
import uuid
import json
import hashlib
import time
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

def diagnose_group_spread(
    groups: List[GRPOGroup],
    std_threshold: float = 1e-6
) -> Dict[str, Any]:
    """
    Diagnoses the reward spread across GRPO groups.

    A group whose rollouts all received the same reward carries NO learning signal:
    `compute_group_advantages` returns all-zero advantages for it, so the policy
    gradient for that group is exactly zero. This is the normal state of a young
    pipeline (every candidate fails at the same gate), and it must be visible rather
    than silently producing a meaningless training run.

    Returns:
        {
            "total_groups": int,
            "degenerate_groups": int,
            "informative_groups": int,
            "degenerate_ratio": float,
            "mean_group_std": float,
            "mean_abs_advantage": float,
            "total_rollouts": int,
            "degenerate_group_ids": List[str],
        }
    """
    degenerate: List[str] = []
    stds: List[float] = []
    all_advantages: List[float] = []

    for g in groups:
        stds.append(float(g.std_reward))
        for r in g.rollouts:
            all_advantages.append(abs(float(r.advantage)))
        if float(g.std_reward) < std_threshold:
            degenerate.append(g.group_id)

    total = len(groups)
    return {
        "total_groups": total,
        "degenerate_groups": len(degenerate),
        "informative_groups": total - len(degenerate),
        "degenerate_ratio": (len(degenerate) / total) if total else 0.0,
        "mean_group_std": (sum(stds) / len(stds)) if stds else 0.0,
        "mean_abs_advantage": (sum(all_advantages) / len(all_advantages)) if all_advantages else 0.0,
        "total_rollouts": len(all_advantages),
        "degenerate_group_ids": degenerate,
    }


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

        # Defense-in-depth: exclude synthetic controls and non-trainable/unfinalized rollouts (Round 5.4)
        if r.get("is_synthetic") is True:
            continue
        if r.get("trainable") is False:
            continue
        if r.get("is_finalized") is False:
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


def evaluate_trajectory_eligibility(
    raw_data: Any,
    seen_trajectory_ids: Optional[set] = None,
    seen_candidate_ids: Optional[set] = None,
    require_exact_tokens: bool = True,
    target_partition: str = "production",
    target_split: str = "train"
) -> Dict[str, Any]:
    """
    Unified validation and eligibility evaluator for both the GRPO data loader
    and the read-only storage audit (Round 5.4).
    
    CRITICAL POLICY:
    Performs raw JSON inspection BEFORE schema instantiation to prevent Pydantic defaults
    from fabricating eligibility on legacy or unprovenanced records.
    """
    if not isinstance(raw_data, dict):
        return {
            "is_eligible": False,
            "rejection_reason": "raw_data_not_a_dict",
            "schema_valid": False,
            "schema_error": f"Expected dict, got {type(raw_data).__name__}",
            "exact_token_eligible": False,
            "raw_inspection": {},
            "trajectory": None
        }

    raw_part = raw_data.get("dataset_partition")
    raw_synth = raw_data.get("is_synthetic")
    raw_train = raw_data.get("trainable")
    raw_fin = raw_data.get("is_finalized")
    raw_prov = raw_data.get("token_provenance")
    raw_split = raw_data.get("dataset_split")
    raw_cat = raw_data.get("category")
    raw_tok_ids = raw_data.get("generated_token_ids")
    raw_traj_id = raw_data.get("trajectory_id")
    raw_cand_id = raw_data.get("candidate_id")

    has_tok_ids = raw_tok_ids is not None and isinstance(raw_tok_ids, list)
    tok_ids_len = len(raw_tok_ids) if has_tok_ids else 0
    valid_tok_types = (
        has_tok_ids and tok_ids_len > 0 and 
        all(isinstance(t, int) and not isinstance(t, bool) and t >= 0 for t in raw_tok_ids)
    )

    prompt_text = raw_data.get("prompt_used", "")
    prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest() if prompt_text else None
    completion_text = raw_data.get("full_completion_text", raw_data.get("raw_model_response", ""))
    exploit_text = raw_data.get("generated_exploit", "")
    exploit_hash = hashlib.sha256(exploit_text.encode("utf-8")).hexdigest() if exploit_text else None

    raw_inspection = {
        "trajectory_id": raw_traj_id,
        "candidate_id": raw_cand_id,
        "raw_partition": raw_part,
        "raw_synthetic": raw_synth,
        "raw_trainable": raw_train,
        "raw_finalized": raw_fin,
        "raw_token_provenance": raw_prov,
        "raw_dataset_split": raw_split,
        "raw_category": str(raw_cat) if raw_cat is not None else None,
        "token_ids_present": has_tok_ids,
        "token_ids_len": tok_ids_len,
        "token_ids_valid_types": valid_tok_types,
        "prompt_sha256": prompt_hash,
        "prompt_len": len(prompt_text) if prompt_text else 0,
        "completion_len": len(completion_text) if completion_text else 0,
        "exploit_sha256": exploit_hash,
        "exploit_len": len(exploit_text) if exploit_text else 0
    }

    # Step 1: Check mandatory raw JSON fields presence BEFORE Pydantic schema
    raw_missing_reason = None
    if "trajectory_id" not in raw_data or not str(raw_traj_id or "").strip():
        raw_missing_reason = "missing_raw_trajectory_id"
    elif "candidate_id" not in raw_data or not str(raw_cand_id or "").strip():
        raw_missing_reason = "missing_raw_candidate_id"
    elif "dataset_partition" not in raw_data:
        raw_missing_reason = "missing_raw_dataset_partition"
    elif "is_synthetic" not in raw_data:
        raw_missing_reason = "missing_raw_is_synthetic"
    elif "trainable" not in raw_data:
        raw_missing_reason = "missing_raw_trainable"
    elif "is_finalized" not in raw_data:
        raw_missing_reason = "missing_raw_is_finalized"
    elif "token_provenance" not in raw_data:
        raw_missing_reason = "missing_raw_token_provenance"
    elif "generated_token_ids" not in raw_data:
        raw_missing_reason = "missing_raw_generated_token_ids"
    elif "dataset_split" not in raw_data:
        raw_missing_reason = "missing_raw_dataset_split"
    elif "category" not in raw_data:
        raw_missing_reason = "missing_raw_category"

    # Step 2: Validate Pydantic schema
    schema_valid = False
    schema_error = None
    traj_obj = None
    try:
        traj_obj = RLVRTrajectory(**raw_data)
        schema_valid = True
    except Exception as exc:
        schema_valid = False
        schema_error = f"{type(exc).__name__}: {str(exc)}"

    # Step 3: Determine training eligibility
    rejection_reason = None
    if raw_missing_reason is not None:
        rejection_reason = raw_missing_reason
    elif not schema_valid:
        rejection_reason = f"schema_validation_error: {schema_error}"
    else:
        # Check domain eligibility criteria
        if traj_obj.category == ResultCategory.INFRA_ERROR or str(raw_cat).endswith("INFRA_ERROR"):
            rejection_reason = "infra_error_category"
        elif raw_fin is not True or traj_obj.is_finalized is not True:
            rejection_reason = "unfinalized_trajectory"
        elif raw_synth is not False or traj_obj.is_synthetic is not False:
            rejection_reason = "synthetic_trajectory"
        elif raw_part != target_partition or traj_obj.dataset_partition != target_partition:
            rejection_reason = f"partition_mismatch_{raw_part}"
        elif raw_train is not True or traj_obj.trainable is not True:
            rejection_reason = "non_trainable"
        elif raw_split != target_split or traj_obj.dataset_split != target_split:
            rejection_reason = f"split_mismatch_{raw_split}"
        elif require_exact_tokens:
            if raw_prov != "model_generate" or traj_obj.token_provenance != "model_generate":
                rejection_reason = f"token_provenance_not_model_generate_{raw_prov}"
            elif raw_tok_ids is None or traj_obj.generated_token_ids is None:
                rejection_reason = "missing_generated_token_ids"
            elif not isinstance(raw_tok_ids, list) or len(raw_tok_ids) == 0:
                rejection_reason = "empty_generated_token_ids"
            elif not valid_tok_types:
                rejection_reason = "invalid_token_id_types"

        # Check deduplication
        if rejection_reason is None:
            if seen_trajectory_ids is not None and traj_obj.trajectory_id in seen_trajectory_ids:
                rejection_reason = "duplicate_trajectory_id"
            elif seen_candidate_ids is not None and traj_obj.candidate_id and traj_obj.candidate_id in seen_candidate_ids:
                rejection_reason = "duplicate_candidate_id"

    is_eligible = (rejection_reason is None)
    exact_token_eligible = (
        is_eligible and 
        raw_prov == "model_generate" and 
        valid_tok_types
    )

    return {
        "is_eligible": is_eligible,
        "rejection_reason": rejection_reason,
        "schema_valid": schema_valid,
        "schema_error": schema_error,
        "exact_token_eligible": exact_token_eligible,
        "raw_inspection": raw_inspection,
        "trajectory": traj_obj if schema_valid else None
    }


def load_trajectories_from_directory(
    trajectory_dir: str,
    target_split: str = "train",
    target_partition: str = "production",
    require_exact_tokens: bool = True
) -> List[Dict[str, Any]]:
    """
    Loads, schema-validates, and deduplicates JSON trajectory files from the persistent volume.
    
    CRITICAL POLICIES (ROUND 4 & ROUND 5.4):
    1. Schema & Invariant Validation: Validates records using RLVRTrajectory. Inconsistent or unfinalized records are rejected.
    2. Strict Production Allowlist (Round 5.2 / Round 5.4):
       - Only records with dataset_partition == target_partition ('production')
       - is_synthetic MUST be False
       - trainable MUST be True
       - category MUST NOT be INFRA_ERROR
       - dataset_split MUST match target_split
    3. Fail-Closed on Missing / Inconsistent Provenance:
       - Records with unknown partition or synthetic origin are strictly excluded from production training.
       - Missing fields in raw JSON are NEVER populated by schema defaults.
    4. Exact Token Lineage is MANDATORY by default (Round 5.4):
       - Default require_exact_tokens=True enforces token_provenance == 'model_generate' and valid generated_token_ids.
       - External API records marked 'external_text_only' cannot enter GRPO training.
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

                eval_res = evaluate_trajectory_eligibility(
                    raw_data=data,
                    seen_trajectory_ids=seen_trajectory_ids,
                    seen_candidate_ids=seen_candidate_ids,
                    require_exact_tokens=require_exact_tokens,
                    target_partition=target_partition,
                    target_split=target_split
                )

                if eval_res["is_eligible"] and eval_res["trajectory"] is not None:
                    seen_trajectory_ids.add(eval_res["trajectory"].trajectory_id)
                    if eval_res["trajectory"].candidate_id:
                        seen_candidate_ids.add(eval_res["trajectory"].candidate_id)
                    records.append(eval_res["trajectory"].model_dump())
            except Exception:
                # Malformed or inconsistent trajectory rejected (fail closed)
                pass

    return records


def load_production_trajectories(
    trajectory_dir: str,
    target_split: str = "train"
) -> List[Dict[str, Any]]:
    """
    Strict production entrypoint for GRPO training (Round 5.4).
    Enforces target_partition='production' and require_exact_tokens=True fail-closed.
    """
    return load_trajectories_from_directory(
        trajectory_dir=trajectory_dir,
        target_split=target_split,
        target_partition="production",
        require_exact_tokens=True
    )


def legacy_load_trajectories_for_inspection(
    trajectory_dir: str,
    target_split: str = "train",
    target_partition: str = "production"
) -> List[Dict[str, Any]]:
    """
    LEGACY READ-ONLY INSPECTION LOADER (Round 5.4).
    STRICTLY PROHIBITED FROM USE IN GRPO TRAINING PATHWAY.
    Use only for post-mortem analysis, historical comparison, or legacy data exploration.
    """
    return load_trajectories_from_directory(
        trajectory_dir=trajectory_dir,
        target_split=target_split,
        target_partition=target_partition,
        require_exact_tokens=False
    )


def audit_trajectory_storage(trajectory_dir: str) -> Dict[str, Any]:
    """
    Performs a strict read-only audit of existing trajectories in the specified directory (Round 5.4).
    Inspects raw JSON before schema validation to prevent schema default fabrication.
    Does NOT alter, migrate, or delete any existing trajectory files.
    """
    report: Dict[str, Any] = {
        "trajectory_dir": trajectory_dir,
        "total_files": 0,
        "json_parse_valid_count": 0,
        "json_parse_error_count": 0,
        "schema_valid_count": 0,
        "malformed_count": 0,
        "loader_eligible_count": 0,
        "exact_token_eligible_count": 0,
        "production_eligible_for_grpo": 0,
        "rejected_count": 0,
        "rejection_reasons": {},
        "by_partition": {"production": 0, "synthetic_control": 0, "test": 0, "missing_or_other": 0},
        "by_synthetic": {"synthetic": 0, "non_synthetic": 0, "missing": 0},
        "by_trainable": {"trainable": 0, "non_trainable": 0, "missing": 0},
        "by_token_provenance": {"model_generate": 0, "external_text_only": 0, "synthetic": 0, "missing": 0},
        "by_category": {},
        "file_records": [],
        "audit_timestamp": time.time()
    }

    if not os.path.exists(trajectory_dir):
        return report

    audit_seen_trajs = set()
    audit_seen_cands = set()

    for fname in sorted(os.listdir(trajectory_dir)):
        if fname.endswith(".json") and fname.startswith("traj_"):
            report["total_files"] += 1
            fpath = os.path.join(trajectory_dir, fname)
            raw_data = None
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                report["json_parse_valid_count"] += 1
            except Exception as e:
                report["json_parse_error_count"] += 1
                report["malformed_count"] += 1
                report["rejected_count"] += 1
                report["by_partition"]["missing_or_other"] += 1
                report["by_synthetic"]["missing"] += 1
                report["by_trainable"]["missing"] += 1
                report["by_token_provenance"]["missing"] += 1
                cat_str = "MALFORMED_JSON"
                report["by_category"][cat_str] = report["by_category"].get(cat_str, 0) + 1
                reason = f"json_parse_error: {type(e).__name__}"
                report["rejection_reasons"][reason] = report["rejection_reasons"].get(reason, 0) + 1
                report["file_records"].append({
                    "filename": fname,
                    "trajectory_id": None,
                    "candidate_id": None,
                    "json_parse_valid": False,
                    "schema_valid": False,
                    "is_eligible": False,
                    "exact_token_eligible": False,
                    "rejection_reason": reason
                })
                continue

            # RAW stats aggregation
            raw_part = raw_data.get("dataset_partition") if isinstance(raw_data, dict) else None
            if raw_part in ("production", "synthetic_control", "test"):
                report["by_partition"][raw_part] += 1
            else:
                report["by_partition"]["missing_or_other"] += 1

            raw_synth = raw_data.get("is_synthetic") if isinstance(raw_data, dict) else None
            if raw_synth is True:
                report["by_synthetic"]["synthetic"] += 1
            elif raw_synth is False:
                report["by_synthetic"]["non_synthetic"] += 1
            else:
                report["by_synthetic"]["missing"] += 1

            raw_train = raw_data.get("trainable") if isinstance(raw_data, dict) else None
            if raw_train is True:
                report["by_trainable"]["trainable"] += 1
            elif raw_train is False:
                report["by_trainable"]["non_trainable"] += 1
            else:
                report["by_trainable"]["missing"] += 1

            raw_prov = raw_data.get("token_provenance") if isinstance(raw_data, dict) else None
            if raw_prov in ("model_generate", "external_text_only", "synthetic"):
                report["by_token_provenance"][raw_prov] += 1
            else:
                report["by_token_provenance"]["missing"] += 1

            cat_str = str(raw_data.get("category", "UNKNOWN")) if isinstance(raw_data, dict) else "UNKNOWN"
            report["by_category"][cat_str] = report["by_category"].get(cat_str, 0) + 1

            # Unified eligibility evaluation (Round 5.4)
            eval_res = evaluate_trajectory_eligibility(
                raw_data=raw_data,
                seen_trajectory_ids=audit_seen_trajs,
                seen_candidate_ids=audit_seen_cands,
                require_exact_tokens=True,
                target_partition="production",
                target_split="train"
            )

            if eval_res["schema_valid"]:
                report["schema_valid_count"] += 1
            else:
                report["malformed_count"] += 1

            if eval_res["is_eligible"]:
                report["loader_eligible_count"] += 1
                if eval_res["trajectory"] is not None:
                    audit_seen_trajs.add(eval_res["trajectory"].trajectory_id)
                    if eval_res["trajectory"].candidate_id:
                        audit_seen_cands.add(eval_res["trajectory"].candidate_id)
            else:
                report["rejected_count"] += 1
                rej_reason = eval_res["rejection_reason"] or "unknown_rejection"
                report["rejection_reasons"][rej_reason] = report["rejection_reasons"].get(rej_reason, 0) + 1

            if eval_res["exact_token_eligible"]:
                report["exact_token_eligible_count"] += 1

            # Safe file record (NO raw prompts, completions, or exploit code)
            safe_rec = {
                "filename": fname,
                "trajectory_id": eval_res["raw_inspection"].get("trajectory_id"),
                "candidate_id": eval_res["raw_inspection"].get("candidate_id"),
                "json_parse_valid": True,
                "schema_valid": eval_res["schema_valid"],
                "is_eligible": eval_res["is_eligible"],
                "exact_token_eligible": eval_res["exact_token_eligible"],
                "rejection_reason": eval_res["rejection_reason"],
                "raw_partition": eval_res["raw_inspection"].get("raw_partition"),
                "raw_synthetic": eval_res["raw_inspection"].get("raw_synthetic"),
                "raw_trainable": eval_res["raw_inspection"].get("raw_trainable"),
                "raw_finalized": eval_res["raw_inspection"].get("raw_finalized"),
                "raw_token_provenance": eval_res["raw_inspection"].get("raw_token_provenance"),
                "token_ids_present": eval_res["raw_inspection"].get("token_ids_present"),
                "token_ids_len": eval_res["raw_inspection"].get("token_ids_len"),
                "prompt_sha256": eval_res["raw_inspection"].get("prompt_sha256"),
                "prompt_len": eval_res["raw_inspection"].get("prompt_len"),
                "completion_len": eval_res["raw_inspection"].get("completion_len"),
                "exploit_sha256": eval_res["raw_inspection"].get("exploit_sha256"),
                "exploit_len": eval_res["raw_inspection"].get("exploit_len")
            }
            report["file_records"].append(safe_rec)

    report["valid_schema_count"] = report["schema_valid_count"]
    report["production_eligible_for_grpo"] = report["loader_eligible_count"]
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
    # FAIL-CLOSED SECURITY GATE (Round 5.4)
    # Strictly prevents execution if training status is BLOCKED
    training_status = os.environ.get("TRAINING_STATUS", "BLOCKED")
    if training_status == "BLOCKED" or getattr(config, "TRAINING_BLOCKED", True):
        raise RuntimeError(
            "FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED. "
            "GRPO policy gradient updates and optimizer.step() are strictly prohibited by AI Supervisor. "
            "Execution aborted fail-closed."
        )

    all_step_stats: List[GRPOTrainingStepStats] = []
    if not groups:
        return all_step_stats

    # Fail-closed: a training run in which EVERY group is degenerate produces an
    # all-zero policy gradient. Such a run cannot teach the model anything, so it
    # must fail loudly instead of silently reporting a meaningless loss.
    spread = diagnose_group_spread(groups)
    print(f"[*] Group reward spread: {spread['informative_groups']}/{spread['total_groups']} informative "
          f"(degenerate_ratio={spread['degenerate_ratio']:.2f}, mean_group_std={spread['mean_group_std']:.4f}, "
          f"mean_abs_advantage={spread['mean_abs_advantage']:.4f})")
    if spread["informative_groups"] == 0 and spread["total_groups"] > 0:
        raise ValueError(
            "Fail-closed: every GRPO group is degenerate (all rollouts share an identical reward). "
            "The policy gradient would be exactly zero and no learning can occur. "
            "Collect trajectories with reward diversity within each prompt group before training."
        )

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
