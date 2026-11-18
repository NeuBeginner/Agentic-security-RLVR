"""Regression tests for the three issues found in the security review screenshot."""

from pathlib import Path

from core.config import PipelineConfig
from core.grpo_trainer import prepare_rollout_tokens


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


def test_pipeline_config_exposes_fail_closed_training_flag():
    cfg = PipelineConfig()
    assert cfg.TRAINING_BLOCKED is True


def test_long_rollout_truncation_preserves_complete_system_prompt():
    tokenizer = CharacterTokenizer()
    system = "<|im_start|>system\nKeep all security rules.\n<|im_end|>"
    prompt = system + "\n<|im_start|>user\n" + ("old context " * 80) + "latest request"
    completion = "candidate output"

    system_tokens = tokenizer.encode(system, add_special_tokens=False)
    input_ids, attention_mask, completion_mask = prepare_rollout_tokens(
        prompt_str=prompt,
        completion_str=completion,
        tokenizer=tokenizer,
        device="cpu",
        max_seq_len=len(system_tokens) + 48,
    )

    actual = input_ids[0].tolist()
    assert actual[:len(system_tokens)] == system_tokens
    assert len(actual) <= len(system_tokens) + 48
    assert attention_mask.shape == input_ids.shape
    assert completion_mask.shape == input_ids.shape
    assert completion_mask.sum().item() > 0
