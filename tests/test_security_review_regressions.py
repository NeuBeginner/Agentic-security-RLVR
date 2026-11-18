"""Regression tests for the three issues found in the security review screenshot."""

import os
from pathlib import Path

import pytest

from core.config import PipelineConfig, is_training_blocked
from core.grpo_trainer import (
    RolloutTooLongError,
    UnsafeRolloutError,
    overlength_diagnostics,
    prepare_rollout_tokens,
    reset_overlength_diagnostics,
)


class CharacterTokenizer:
    """Deterministic tokenizer stub that keeps prefix tokenization stable."""

    bos_token = None
    eos_token_id = 999

    def encode(self, text, add_special_tokens=True):
        tokens = [ord(char) for char in text]
        return ([1] + tokens) if add_special_tokens else tokens


def test_exploit_module_is_written_only_under_foundry_test_dir():
    source = (Path(__file__).resolve().parents[1] / "sandbox" / "runner.py").read_text()
    assert 'os.path.join(test_dir, safe_filename)' in source
    assert 'os.path.join(src_dir, safe_filename)' not in source


def test_the_candidate_is_written_only_under_the_test_dir_of_the_local_adapter():
    source = (Path(__file__).resolve().parents[1] / "benchmarks" / "adapters.py").read_text()
    assert 'os.path.join(test_dir, "ExploitModule.sol")' in source
    assert 'os.path.join(src_dir, "ExploitModule.sol")' not in source


def test_the_training_gate_is_blocked_by_default():
    """The gate is decided by the live environment, not by an import-time value."""
    cfg = PipelineConfig()
    assert cfg.TRAINING_BLOCKED is True

    previous_status = os.environ.pop("TRAINING_STATUS", None)
    previous_flag = os.environ.pop("TRAINING_BLOCKED", None)
    try:
        assert is_training_blocked(cfg) is True
    finally:
        if previous_status is not None:
            os.environ["TRAINING_STATUS"] = previous_status
        if previous_flag is not None:
            os.environ["TRAINING_BLOCKED"] = previous_flag


def test_the_training_gate_is_read_at_the_moment_of_the_call():
    """A value that the operator changes after the import is honoured."""
    previous_status = os.environ.get("TRAINING_STATUS")
    previous_flag = os.environ.get("TRAINING_BLOCKED")
    try:
        os.environ["TRAINING_STATUS"] = "BLOCKED"
        os.environ["TRAINING_BLOCKED"] = "true"
        assert is_training_blocked(PipelineConfig()) is True

        os.environ["TRAINING_STATUS"] = "UNBLOCKED"
        os.environ["TRAINING_BLOCKED"] = "false"
        assert is_training_blocked(PipelineConfig()) is False
    finally:
        if previous_status is None:
            os.environ.pop("TRAINING_STATUS", None)
        else:
            os.environ["TRAINING_STATUS"] = previous_status
        if previous_flag is None:
            os.environ.pop("TRAINING_BLOCKED", None)
        else:
            os.environ["TRAINING_BLOCKED"] = previous_flag


def test_a_contradictory_training_gate_names_both_variables():
    """A contradiction is refused, and the error names both variables."""
    previous_status = os.environ.get("TRAINING_STATUS")
    previous_flag = os.environ.get("TRAINING_BLOCKED")
    try:
        os.environ["TRAINING_STATUS"] = "UNBLOCKED"
        os.environ["TRAINING_BLOCKED"] = "true"
        with pytest.raises(RuntimeError) as excinfo:
            is_training_blocked(PipelineConfig())
        message = str(excinfo.value)
        assert "TRAINING_STATUS" in message
        assert "TRAINING_BLOCKED" in message
    finally:
        if previous_status is None:
            os.environ.pop("TRAINING_STATUS", None)
        else:
            os.environ["TRAINING_STATUS"] = previous_status
        if previous_flag is None:
            os.environ.pop("TRAINING_BLOCKED", None)
        else:
            os.environ["TRAINING_BLOCKED"] = previous_flag


def test_a_rollout_that_does_not_fit_is_skipped_and_not_truncated():
    """
    A rollout that does not fit into the budget is refused.

    The old behaviour cut the whole context away (the contract source of the
    prompt) and trained on the remainder - a prompt that never existed in the
    EVM. The rollout is now refused, and the refusal is counted.
    """
    tokenizer = CharacterTokenizer()
    system = "<|im_start|>system\nKeep all security rules.\n<|im_end|>"
    prompt = system + "\n<|im_start|>user\n" + ("old context " * 80) + "latest request"
    completion = "candidate output"

    system_tokens = tokenizer.encode(system, add_special_tokens=False)
    completion_tokens = len(tokenizer.encode(completion, add_special_tokens=False)) + 1  # + the EOS

    # The budget leaves no room for the context: the whole contract source of
    # the prompt would be cut away.
    reset_overlength_diagnostics()
    try:
        with pytest.raises(RolloutTooLongError) as excinfo:
            prepare_rollout_tokens(
                prompt_str=prompt,
                completion_str=completion,
                tokenizer=tokenizer,
                device="cpu",
                max_seq_len=len(system_tokens) + completion_tokens,
            )
        assert "context_budget" in str(excinfo.value)
    finally:
        reset_overlength_diagnostics()


def test_a_rollout_that_fits_keeps_the_system_prompt_and_the_eos_token():
    """A rollout that fits keeps the system prompt, the context and the EOS token."""
    tokenizer = CharacterTokenizer()
    system = "<|im_start|>system\nKeep all security rules.\n<|im_end|>"
    prompt = system + "\n<|im_start|>user\n" + ("old context " * 20) + "latest request"
    completion = "candidate output"

    system_tokens = tokenizer.encode(system, add_special_tokens=False)

    input_ids, attention_mask, completion_mask = prepare_rollout_tokens(
        prompt_str=prompt,
        completion_str=completion,
        tokenizer=tokenizer,
        device="cpu",
        max_seq_len=len(system_tokens) + 120,
    )

    actual = input_ids[0].tolist()
    assert actual[:len(system_tokens)] == system_tokens
    assert len(actual) <= len(system_tokens) + 120
    assert attention_mask.shape == input_ids.shape
    assert completion_mask.shape == input_ids.shape
    assert completion_mask.sum().item() > 0
    # The end-of-sequence token is the boundary of the completion: it is never
    # cut away by the truncation.
    assert actual[-1] == tokenizer.eos_token_id


def test_a_rollout_without_a_prompt_is_refused():
    """A rollout without a prompt carries nothing to learn from."""

    class EmptyPromptTokenizer(CharacterTokenizer):
        def encode(self, text, add_special_tokens=True):
            if not text:
                return []
            return super().encode(text, add_special_tokens=add_special_tokens)

    with pytest.raises(UnsafeRolloutError):
        prepare_rollout_tokens(
            prompt_str="",
            completion_str="candidate output",
            tokenizer=EmptyPromptTokenizer(),
            device="cpu",
        )


def test_the_skipped_rollouts_are_counted():
    """The skips of the trainer are a diagnostic, not a silent loss."""
    reset_overlength_diagnostics()
    try:
        assert overlength_diagnostics()["skipped_rollouts"] == 0
        from core.grpo_trainer import _record_overlength_skip

        _record_overlength_skip("the rollout does not fit")
        _record_overlength_skip("the rollout does not fit")
        diagnostics = overlength_diagnostics()
        assert diagnostics["skipped_rollouts"] == 2
        assert diagnostics["last_reason"] == "the rollout does not fit"
        assert diagnostics["reasons"]["the rollout does not fit"] == 2
    finally:
        reset_overlength_diagnostics()
