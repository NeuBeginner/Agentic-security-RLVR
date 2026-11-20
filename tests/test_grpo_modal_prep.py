"""
tests/test_grpo_modal_prep.py

Unit tests for GRPO PoC / Modal preparation:
1. Validates GRPO config defaults: GRPO_GPU_TYPE == "H100",
   GRPO_BASE_MODEL == "Qwen/Qwen2.5-Coder-1.5B-Instruct", TRAINING_BLOCKED is True.
2. Validates fail-closed refusal of train_grpo_remote when TRAINING_STATUS=BLOCKED.
3. Validates strict data isolation of collect_train_rollouts_remote (zero overlap
   with the 16 benchmark test targets).
4. Validates bitsandbytes package in gpu_image and model_volume.reload() calls.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch
import pytest

from core.config import config, is_training_blocked, PipelineConfig
from core.llm_generator import build_exploit_engineer_system_prompt
from core.schemas import ExecutionResult, ResultCategory, TargetProgram
from core.train_rollout_collector import (
    load_train_targets,
    validate_train_target_isolation,
    TrainRolloutCollectionResult,
)
from sandbox.runner import (
    TRUSTED_HARNESS_CONTRACTS,
    TRAIN_TRUSTED_HARNESS_CONTRACTS,
)
import modal_app
from core import r1_bounds as r1


def _get_raw_callable(guarded_obj) -> callable:
    """Helper to extract the underlying Python callable from GuardedRemote."""
    token = guarded_obj.__dict__["_object_token"]
    raw_modal_fn = r1._GUARDED_OBJECTS[token]
    return getattr(raw_modal_fn, "_raw_f_", None) or raw_modal_fn.get_raw_f()


# =============================================================================
# 1. Configuration tests
# =============================================================================

def test_grpo_config_defaults():
    """Verify GRPO PoC config defaults and unchanged critical constants."""
    assert config.GRPO_GPU_TYPE == "H100"
    assert config.GRPO_BASE_MODEL == "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    assert config.TRAINING_BLOCKED is True
    assert config.DEV_GPU_MODEL == "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    assert config.DEV_GPU_TYPE == "T4"
    assert config.AUDIT_GPU_MODEL == "qtum/Qwen3-Coder-30B-A3B-Audit"
    assert config.AUDIT_GPU_TYPE == "H100"

    # Default live environment gate must be fail-closed
    with patch.dict(os.environ, {}, clear=True):
        assert is_training_blocked() is True
        assert is_training_blocked(config) is True


# =============================================================================
# 2. Fail-closed security gate tests for train_grpo_remote
# =============================================================================

def test_train_grpo_remote_fail_closed_when_blocked():
    """Verify train_grpo_remote fails closed immediately when TRAINING_STATUS=BLOCKED."""
    fn = _get_raw_callable(modal_app.train_grpo_remote)

    with patch.dict(os.environ, {"TRAINING_STATUS": "BLOCKED"}, clear=True):
        with pytest.raises(RuntimeError, match="FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED"):
            fn()


def test_train_grpo_remote_fail_closed_when_env_unset():
    """Verify train_grpo_remote fails closed by default when env vars are unset."""
    fn = _get_raw_callable(modal_app.train_grpo_remote)

    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(RuntimeError, match="FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED"):
            fn()


def test_train_grpo_remote_fail_closed_on_contradictory_env():
    """Verify contradictory flags raise a fail-closed RuntimeError."""
    fn = _get_raw_callable(modal_app.train_grpo_remote)

    with patch.dict(os.environ, {"TRAINING_STATUS": "ENABLED", "TRAINING_BLOCKED": "1"}, clear=True):
        with pytest.raises(RuntimeError, match="FAIL-CLOSED SECURITY GATE: the training gate is contradictory"):
            fn()


# =============================================================================
# 3. Data isolation and collect_train_rollouts_remote tests
# =============================================================================

def test_collect_train_rollouts_remote_train_isolation():
    """Verify that train targets have zero overlap with test targets and test targets are refused."""
    train_targets = load_train_targets()
    assert len(train_targets) == 20

    test_target_names = set(TRUSTED_HARNESS_CONTRACTS.keys())
    assert len(test_target_names) == 16

    for target in train_targets:
        assert target.name not in test_target_names
        assert target.name in TRAIN_TRUSTED_HARNESS_CONTRACTS

    # Test target must be rejected by isolation validator
    test_target = TargetProgram(
        name="Vault",
        source_code="contract Vault { function deposit() external payable {} }",
        language="solidity",
    )
    with pytest.raises(ValueError, match="Data isolation violation: target 'Vault' belongs to the test split"):
        validate_train_target_isolation(test_target)


def test_collect_train_rollouts_remote_mock_execution():
    """Verify collect_train_rollouts_remote behavior, argument slicing, verifier delegation, prompt, and gpu_image."""
    import ast
    from pathlib import Path
    import torch

    fn = _get_raw_callable(modal_app.collect_train_rollouts_remote)

    with patch("core.train_rollout_collector.load_train_targets") as mock_load, \
         patch("transformers.AutoTokenizer.from_pretrained") as mock_tok, \
         patch("transformers.AutoModelForCausalLM.from_pretrained") as mock_model, \
         patch("core.train_rollout_collector.collect_train_rollouts") as mock_collect, \
         patch.object(modal_app.verify_train_exploit_remote, "remote") as mock_verify_remote, \
         patch.object(modal_app.model_volume, "reload") as mock_reload, \
         patch.object(modal_app.model_volume, "commit") as mock_commit:

        t1 = TargetProgram(name="TrainPushAuction", source_code="contract TrainPushAuction {}", language="solidity")
        t2 = TargetProgram(name="TrainFeeRoundingVault", source_code="contract TrainFeeRoundingVault {}", language="solidity")
        mock_load.return_value = [t1, t2]

        tok_mock = MagicMock()
        tok_mock.pad_token = None
        tok_mock.eos_token = "<eos>"
        tok_mock.pad_token_id = 0
        tok_mock.eos_token_id = 1
        tok_mock.apply_chat_template.return_value = "<chatml> prompt"
        encoded_inputs = MagicMock()
        encoded_inputs.__getitem__.side_effect = lambda k: torch.tensor([[10, 11]])
        encoded_inputs.get.return_value = torch.tensor([[1, 1]])
        encoded_inputs.to.return_value = encoded_inputs
        tok_mock.return_value = encoded_inputs
        tok_mock.decode.return_value = (
            '{"vulnerability_type": "DoS", "reasoning_trace": "r", '
            '"attack_vector": "v", "test_code": "contract ExploitModule { function runExploit() external payable {} }"}'
        )
        mock_tok.return_value = tok_mock

        model_mock = MagicMock()
        model_mock.generate.return_value = torch.tensor([[10, 11, 21, 22, 23]])
        mock_model.return_value.to.return_value = model_mock

        mock_verify_remote.return_value = ExecutionResult(
            return_code=0,
            stdout="ok",
            stderr="",
            execution_time_sec=0.1,
            category=ResultCategory.EXPLOIT_CONFIRMED,
            invariant_violated=True,
            test_status="Success",
            verified_by_harness=True,
        ).model_dump()

        captured_messages = []
        captured_exec_results = []

        def _collect_side_effect(**kwargs):
            gen_fn = kwargs["generator_fn"]
            ver_fn = kwargs["verifier_fn"]
            target = kwargs["targets"][0]
            payload = gen_fn(target, "analyze this target", 0.7, 0)
            captured_messages.append(tok_mock.apply_chat_template.call_args.args[0])
            captured_exec_results.append((target, payload, ver_fn(target, payload)))
            return TrainRolloutCollectionResult(
                run_id="run_poc_test",
                trajectory_dir=config.TRAJECTORY_DIR,
                targets_processed=1,
                candidates_generated=4,
                persisted_count=3,
                excluded_infra_count=1,
                excluded_missing_tokens_count=0,
                category_counts={"EXPLOIT_CONFIRMED": 1, "SAFE_RUN": 2},
                group_spread={"group_count": 1, "informative_groups": 1},
            )

        mock_collect.side_effect = _collect_side_effect

        res = fn(max_targets=1, group_size=4)

        assert res["status"] == "success"
        assert res["run_id"] == "run_poc_test"
        assert res["persisted_count"] == 3
        assert res["excluded_infra_count"] == 1
        assert res["category_counts"] == {"EXPLOIT_CONFIRMED": 1, "SAFE_RUN": 2}
        assert res["group_spread"] == {"group_count": 1, "informative_groups": 1}

        # Verify max_targets was applied before passing to collect_train_rollouts
        mock_collect.assert_called_once()
        passed_targets = mock_collect.call_args.kwargs["targets"]
        assert len(passed_targets) == 1
        assert passed_targets[0].name == "TrainPushAuction"

        # Verify system prompt matches build_exploit_engineer_system_prompt(target.name)
        assert len(captured_messages) == 1
        assert captured_messages[0][0]["role"] == "system"
        assert captured_messages[0][0]["content"] == build_exploit_engineer_system_prompt("TrainPushAuction")

        # Verify verifier_fn delegates to verify_train_exploit_remote.remote
        assert len(captured_exec_results) == 1
        tgt_used, pld_used, exec_res = captured_exec_results[0]
        mock_verify_remote.assert_called_once_with(tgt_used.model_dump(), pld_used.model_dump())
        assert isinstance(exec_res, ExecutionResult)
        assert exec_res.category == ResultCategory.EXPLOIT_CONFIRMED

        # Verify gpu_image includes /opt/aegis/benchmarks/... files/dirs with copy=True
        modal_app_path = Path(__file__).resolve().parents[1] / "modal_app.py"
        tree = ast.parse(modal_app_path.read_text(encoding="utf-8"))
        remote_paths = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "gpu_image":
                        for child in ast.walk(node.value):
                            if isinstance(child, ast.Call) and getattr(child.func, "attr", None) in ("add_local_file", "add_local_dir"):
                                copy_kw = [kw.value.value for kw in child.keywords if kw.arg == "copy" and isinstance(kw.value, ast.Constant)]
                                str_args = [a.value for a in child.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                                if copy_kw == [True]:
                                    remote_paths.update(str_args)
        assert {
            "/opt/aegis/benchmarks/train_dataset.json",
            "/opt/aegis/benchmarks/benchmark_dataset.json",
            "/opt/aegis/benchmarks/targets/solidity_train",
            "/opt/aegis/benchmarks/targets/solidity",
        }.issubset(remote_paths)

        # Verify model_volume reload and commit were invoked
        mock_reload.assert_called_once()
        mock_commit.assert_called_once()


# =============================================================================
# 4. Modal app image and volume reload verification
# =============================================================================

def test_gpu_image_bitsandbytes_installed():
    """Verify bitsandbytes>=0.45.0 is included in gpu_image pip_install arguments."""
    import ast
    from pathlib import Path

    modal_app_path = Path(__file__).resolve().parents[1] / "modal_app.py"
    tree = ast.parse(modal_app_path.read_text(encoding="utf-8"))
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "gpu_image":
                    for child in ast.walk(node.value):
                        if isinstance(child, ast.Call) and getattr(child.func, "attr", None) == "pip_install":
                            args = [a.value for a in child.args if isinstance(a, ast.Constant)]
                            if "bitsandbytes>=0.45.0" in args:
                                found = True
    assert found, "bitsandbytes>=0.45.0 must be in gpu_image pip_install"


def test_audit_volume_trajectories_remote_calls_reload():
    """Verify audit_volume_trajectories_remote invokes model_volume.reload()."""
    fn = _get_raw_callable(modal_app.audit_volume_trajectories_remote)

    with patch.object(modal_app.model_volume, "reload") as mock_reload, \
         patch("core.grpo_trainer.audit_trajectory_storage") as mock_audit:
        mock_audit.return_value = {"total_files": 0, "status": "empty"}

        res = fn()
        mock_reload.assert_called_once()
        assert res["status"] == "empty"
