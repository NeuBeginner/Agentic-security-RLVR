import pytest
import math
import torch
import torch.nn as nn
from core.grpo_trainer import (
    compute_group_advantages,
    compute_grpo_loss,
    group_rollouts_by_prompt,
    prepare_rollout_tokens
)
from core.schemas import AttackHypothesis


def test_compute_group_advantages_normal():
    # 4 candidates with different rewards
    rewards = [1.0, -0.5, 0.5, -0.25]
    advs = compute_group_advantages(rewards)

    assert len(advs) == 4
    # The best candidate (+1.0) must have the highest positive advantage
    assert advs[0] > 0
    assert advs[0] == max(advs)
    # The worst candidate (-0.5) must have the lowest negative advantage
    assert advs[1] < 0
    assert advs[1] == min(advs)
    # Sum of standardized advantages is approximately 0
    assert math.isclose(sum(advs), 0.0, abs_tol=1e-5)


def test_compute_group_advantages_identical():
    # All candidates received the identical compilation failure (-0.5)
    rewards = [-0.5, -0.5, -0.5, -0.5]
    advs = compute_group_advantages(rewards)

    assert len(advs) == 4
    # Zero variance must produce strictly 0.0 advantage to avoid gradient explosion
    assert all(a == 0.0 for a in advs)


def test_compute_group_advantages_edge_cases():
    assert compute_group_advantages([]) == []
    assert compute_group_advantages([1.0]) == [0.0]


def test_group_rollouts_by_prompt():
    rollouts_data = [
        {
            "trajectory_id": "t1",
            "target_name": "Vault",
            "prompt_used": "Audit Vault contract",
            "hypothesis": {"vulnerability_type": "Reentrancy", "reasoning_trace": "", "attack_vector": ""},
            "generated_exploit": "contract Exploit1 {}",
            "reward": 1.0,
            "is_verified": True,
            "reproduced": True,
            "feedback_trace": "Breached"
        },
        {
            "trajectory_id": "t2",
            "target_name": "Vault",
            "prompt_used": "Audit Vault contract",
            "hypothesis": {"vulnerability_type": "Reentrancy", "reasoning_trace": "", "attack_vector": ""},
            "generated_exploit": "contract Exploit2 {}",
            "reward": -0.5,
            "is_verified": False,
            "reproduced": False,
            "feedback_trace": "Compile error"
        }
    ]

    groups = group_rollouts_by_prompt(rollouts_data, group_size=2)
    assert len(groups) == 1
    grp = groups[0]
    assert grp.target_name == "Vault"
    assert len(grp.rollouts) == 2
    # Verify relative advantage was computed for rollouts
    assert grp.rollouts[0].advantage > 0
    assert grp.rollouts[1].advantage < 0
    assert grp.rollouts[0].reward == 1.0
    assert grp.rollouts[1].reward == -0.5


def test_prepare_rollout_tokens_exact_boundary():
    class MockTokenizer:
        def __init__(self):
            self.eos_token_id = 999
        def encode(self, text, add_special_tokens=True):
            if "prompt" in text:
                return [10, 20, 30]  # 3 prompt tokens
            return [40, 50]  # 2 completion tokens

    mock_tok = MockTokenizer()
    input_ids, attn_mask, comp_mask = prepare_rollout_tokens(
        prompt_str="prompt code",
        completion_str="completion exploit",
        tokenizer=mock_tok,
        device="cpu",
        max_seq_len=128
    )

    # Prompt: 3 tokens, Completion: 2 tokens + EOS (999) = 3 tokens
    # Total: 6 tokens
    assert input_ids.shape == (1, 6)
    assert input_ids[0].tolist() == [10, 20, 30, 40, 50, 999]

    # Prompt tokens MUST have mask 0.0, completion tokens MUST have mask 1.0
    assert comp_mask[0, :3].tolist() == [0.0, 0.0, 0.0]
    assert comp_mask[0, 3:].tolist() == [1.0, 1.0, 1.0]


def test_compute_grpo_loss_divergent_policy():
    batch_size = 2
    seq_len = 8

    # Active policy logprobs
    policy_logits = torch.randn(batch_size, seq_len, requires_grad=True)
    policy_logprobs = torch.log_softmax(policy_logits, dim=-1)

    # Independent old_logprobs from earlier policy
    old_logits = torch.randn(batch_size, seq_len)
    old_logprobs = torch.log_softmax(old_logits, dim=-1)

    # Frozen reference model logprobs
    ref_logits = torch.randn(batch_size, seq_len)
    ref_logprobs = torch.log_softmax(ref_logits, dim=-1)

    advantages = torch.tensor([1.5, -1.0], dtype=torch.float32)
    completion_mask = torch.ones(batch_size, seq_len, dtype=torch.float32)

    loss, metrics = compute_grpo_loss(
        policy_logprobs=policy_logprobs,
        old_logprobs=old_logprobs,
        advantages=advantages,
        ref_logprobs=ref_logprobs,
        completion_mask=completion_mask,
        clip_eps=0.2,
        beta_kl=0.04
    )

    # Under divergent policy, loss is real, non-zero, and KL is strictly positive
    assert torch.isfinite(loss)
    assert abs(metrics["loss"]) > 1e-4
    assert metrics["kl"] >= 0.0  # KL is strictly non-negative
    assert abs(metrics["mean_ratio"] - 1.0) > 1e-4

    # Backpropagation verification
    loss.backward()
    assert policy_logits.grad is not None
    assert torch.all(torch.isfinite(policy_logits.grad))
