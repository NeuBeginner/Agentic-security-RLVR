"""
tests/test_grpo_integrity.py

Regression test suite for Section 3 (Round 4):
GRPO Grouping Identity and Tokenization Integrity.
"""

import pytest
import torch
from core.grpo_trainer import (
    compute_prompt_hash,
    make_group_key,
    group_rollouts_by_prompt,
    prepare_rollout_tokens,
    compute_group_advantages
)
from core.schemas import ResultCategory


class MockTokenizer:
    """Mock tokenizer simulating BPE behavior, token IDs, and special tokens."""
    def __init__(self):
        self.eos_token_id = 999
        self.pad_token_id = 0
        # Map common words to fixed IDs
        self.vocab = {
            "prompt": 10,
            "prefix": 11,
            "shared": 12,
            "branchA": 13,
            "branchB": 14,
            "completion": 20,
            "def": 21,
            "foo": 22,
            "(": 23,
            ")": 24,
            ":": 25,
            "def foo": 30,  # simulate merged BPE token
        }

    def encode(self, text: str, add_special_tokens: bool = False) -> list[int]:
        tokens = []
        words = text.strip().split()
        for w in words:
            if w in self.vocab:
                tokens.append(self.vocab[w])
            else:
                # Deterministic hash ID
                tokens.append(abs(hash(w)) % 1000 + 100)
        return tokens

    def decode(self, token_ids: list[int], skip_special_tokens: bool = True) -> str:
        inv = {v: k for k, v in self.vocab.items()}
        return " ".join(inv.get(tid, f"tok_{tid}") for tid in token_ids if tid != self.eos_token_id)


def test_collision_resistant_prompt_identity():
    """Test 1: Two prompts sharing the first 80 chars but differing later form different groups."""
    shared_prefix_85_chars = "A" * 85
    prompt_a = shared_prefix_85_chars + " DIFFERENT_SUFFIX_ALPHA"
    prompt_b = shared_prefix_85_chars + " DIFFERENT_SUFFIX_BETA"

    # In old implementation using prompt[:80], both would have identical keys!
    assert prompt_a[:80] == prompt_b[:80]

    # In new implementation using full SHA-256 hash:
    hash_a = compute_prompt_hash(prompt_a)
    hash_b = compute_prompt_hash(prompt_b)
    assert hash_a != hash_b

    key_a = make_group_key("Vault", prompt_a, "model_v1", "ckpt_step_1")
    key_b = make_group_key("Vault", prompt_b, "model_v1", "ckpt_step_1")
    assert key_a != key_b


def test_different_models_and_checkpoints_never_mixed():
    """Test 2: Different model/checkpoint versions must not be mixed into the same group."""
    prompt = "Test security prompt for Vault invariant"
    
    key_base = make_group_key("Vault", prompt, "Qwen-1.5B", "base")
    key_lora = make_group_key("Vault", prompt, "Qwen-1.5B", "checkpoint-step-2")
    key_model2 = make_group_key("Vault", prompt, "Qwen-7B", "base")

    assert key_base != key_lora
    assert key_base != key_model2
    assert key_lora != key_model2


def test_infra_error_excluded_from_group_statistics():
    """Test 3: INFRA_ERROR records must not affect group rewards, means, standard deviations, or advantages."""
    prompt = "Audit Vault deposit solvency"
    
    rollouts_with_infra = [
        {"target_name": "Vault", "prompt_used": prompt, "reward": 0.5, "category": "INVARIANT_BREACH_UNREPLAYED"},
        {"target_name": "Vault", "prompt_used": prompt, "reward": -0.25, "category": "RUNTIME_REVERT"},
        {"target_name": "Vault", "prompt_used": prompt, "reward": 0.0, "category": "INFRA_ERROR"},  # Should be excluded!
    ]

    rollouts_without_infra = [
        {"target_name": "Vault", "prompt_used": prompt, "reward": 0.5, "category": "INVARIANT_BREACH_UNREPLAYED"},
        {"target_name": "Vault", "prompt_used": prompt, "reward": -0.25, "category": "RUNTIME_REVERT"},
    ]

    groups_with = group_rollouts_by_prompt(rollouts_with_infra, group_size=5)
    groups_without = group_rollouts_by_prompt(rollouts_without_infra, group_size=5)

    assert len(groups_with) == 1
    assert len(groups_without) == 1

    # In both cases, only 2 rollouts are present in the group
    assert len(groups_with[0].rollouts) == 2
    assert len(groups_without[0].rollouts) == 2

    # Group mean and std reward must be identical
    assert abs(groups_with[0].mean_reward - groups_without[0].mean_reward) < 1e-6
    assert abs(groups_with[0].std_reward - groups_without[0].std_reward) < 1e-6

    # Advantages must be identical
    advs_with = [r.advantage for r in groups_with[0].rollouts]
    advs_without = [r.advantage for r in groups_without[0].rollouts]
    for aw, awo in zip(advs_with, advs_without):
        assert abs(aw - awo) < 1e-6


def test_prepare_rollout_tokens_with_stored_token_ids():
    """Test 4: When stored_generated_token_ids are provided, exact token sequence is preserved."""
    tokenizer = MockTokenizer()
    prompt = "prompt prefix shared"
    completion = "completion def foo"
    
    # Simulate generation that produced specific token IDs
    stored_ids = [20, 21, 22]

    input_ids, attention_mask, completion_mask = prepare_rollout_tokens(
        prompt_str=prompt,
        completion_str=completion,
        tokenizer=tokenizer,
        device="cpu",
        stored_generated_token_ids=stored_ids
    )

    # Prompt tokens have mask 0.0
    # Completion tokens + EOS have mask 1.0
    prompt_len = len(tokenizer.encode(prompt, add_special_tokens=True))
    assert completion_mask[0, :prompt_len].sum().item() == 0.0
    assert completion_mask[0, prompt_len:].sum().item() == len(stored_ids) + 1  # includes EOS


def test_empty_completion_and_truncation():
    """Test 5: Empty completion produces all-zero completion_mask; sequence truncation behaves safely."""
    tokenizer = MockTokenizer()
    prompt = "prompt prefix"
    empty_completion = ""

    input_ids, attention_mask, completion_mask = prepare_rollout_tokens(
        prompt_str=prompt,
        completion_str=empty_completion,
        tokenizer=tokenizer,
        device="cpu"
    )

    # All tokens are prompt tokens -> completion_mask is 0 everywhere
    assert completion_mask.sum().item() == 0.0

    # Truncation test with max_seq_len
    input_ids_tr, _, _ = prepare_rollout_tokens(
        prompt_str="word " * 50,
        completion_str="completion",
        tokenizer=tokenizer,
        device="cpu",
        max_seq_len=10
    )
    assert input_ids_tr.shape[1] <= 10


# =============================================================================
# STAGE 4: GRPO GROUP INTEGRITY & HYPERPARAMETER ISOLATION TESTS
# =============================================================================

def test_group_key_temperature_and_top_p_isolation():
    """Different sampling temperatures and top-p values must yield distinct GRPO keys."""
    prompt = "Verify Vault solvency"
    key_t07 = make_group_key("Vault", prompt, temperature=0.7, top_p=0.95)
    key_t10 = make_group_key("Vault", prompt, temperature=1.0, top_p=0.95)
    key_p90 = make_group_key("Vault", prompt, temperature=0.7, top_p=0.90)

    assert key_t07 != key_t10
    assert key_t07 != key_p90
    assert "t_0.700" in key_t07
    assert "t_1.000" in key_t10


def test_group_key_system_prompt_isolation():
    """Different system prompts must yield distinct GRPO keys."""
    prompt = "Verify Vault solvency"
    key_sys1 = make_group_key("Vault", prompt, system_prompt="You are an expert security auditor.")
    key_sys2 = make_group_key("Vault", prompt, system_prompt="You are an aggressive white-hat exploiter.")
    key_nosys = make_group_key("Vault", prompt, system_prompt=None)

    assert key_sys1 != key_sys2
    assert key_sys1 != key_nosys
    assert key_sys2 != key_nosys


def test_group_key_generation_params_and_reward_version_isolation():
    """Distinct generation parameters and reward specification versions must not be grouped together."""
    prompt = "Verify Vault solvency"
    key_v1 = make_group_key("Vault", prompt, reward_spec_version="v1")
    key_v2 = make_group_key("Vault", prompt, reward_spec_version="v2")
    assert key_v1 != key_v2
    assert "v1" in key_v1
    assert "v2" in key_v2

    key_gen1 = make_group_key("Vault", prompt, generation_params={"seed": 42, "max_tokens": 512})
    key_gen2 = make_group_key("Vault", prompt, generation_params={"seed": 999, "max_tokens": 512})
    assert key_gen1 != key_gen2


def test_group_rollouts_isolates_incompatible_generation_conditions():
    """Rollouts generated under different temperatures must never be merged into the same GRPOGroup."""
    prompt = "Shared audit prompt"
    rollouts = [
        # 2 rollouts at temperature 0.7
        {"target_name": "Vault", "prompt_used": prompt, "reward": 0.5, "category": "RUNTIME_REVERT", "temperature": 0.7},
        {"target_name": "Vault", "prompt_used": prompt, "reward": -0.2, "category": "RUNTIME_REVERT", "temperature": 0.7},
        # 2 rollouts at temperature 1.0
        {"target_name": "Vault", "prompt_used": prompt, "reward": 0.8, "category": "RUNTIME_REVERT", "temperature": 1.0},
        {"target_name": "Vault", "prompt_used": prompt, "reward": -0.5, "category": "RUNTIME_REVERT", "temperature": 1.0},
    ]
    groups = group_rollouts_by_prompt(rollouts, group_size=2)
    assert len(groups) == 2
    # Verify the two groups are separate
    assert groups[0].group_id != groups[1].group_id
