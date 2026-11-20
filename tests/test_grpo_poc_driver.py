"""
tests/test_grpo_poc_driver.py
=============================

Zero-cost ($0) unit and contract tests for the isolated L4 GRPO PoC contour:
- core.config PoC settings & isolation from production directories
- benchmarks.run_grpo_poc fail-closed gates and --dry-run
- modal_grpo_poc_app.py AST & fail-closed poc_train_grpo gate
- modal_app.py diagnostic_grpo_forward_remote fixes & scaledown_window=60
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_config_grpo_poc_settings_and_isolation():
    from core.config import config

    assert config.GRPO_POC_GPU_TYPE == "L4"
    assert config.GRPO_GPU_TYPE == "H100"
    assert config.GRPO_BASE_MODEL == "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    assert config.TRAINING_BLOCKED is True
    assert config.GRPO_POC_TRAJECTORY_DIR != config.TRAJECTORY_DIR
    assert config.GRPO_POC_CHECKPOINT_DIR != config.GRPO_CHECKPOINT_DIR


def test_run_grpo_poc_fail_closed_without_approval(monkeypatch):
    from benchmarks.run_grpo_poc import APPROVAL_ENV_VAR, GrpoPocNotAuthorised, run_live_poc

    monkeypatch.delenv(APPROVAL_ENV_VAR, raising=False)
    with patch.dict(sys.modules, {"modal": None}):
        with pytest.raises(GrpoPocNotAuthorised):
            run_live_poc(stage="collect-and-diagnose")


def test_run_grpo_poc_train_stage_fail_closed_when_training_blocked(monkeypatch):
    from benchmarks.run_grpo_poc import APPROVAL_ENV_VAR, run_live_poc

    monkeypatch.setenv(APPROVAL_ENV_VAR, "1")
    monkeypatch.delenv("TRAINING_STATUS", raising=False)
    monkeypatch.delenv("TRAINING_BLOCKED", raising=False)

    with patch.dict(sys.modules, {"modal": None}):
        with pytest.raises(RuntimeError, match="TRAINING_STATUS = BLOCKED"):
            run_live_poc(stage="train")


def test_run_grpo_poc_dry_run_validates_10_train_targets_without_modal(capsys):
    from benchmarks.run_grpo_poc import main

    with patch.dict(sys.modules, {"modal": None}):
        exit_code = main(["--dry-run", "--max-targets", "4", "--group-size", "4"])

    assert exit_code == 0
    captured = capsys.readouterr()
    plan = json.loads(captured.out)
    assert plan["mode"] == "dry-run"
    assert plan["cost_usd"] == 0.0
    assert plan["gpu_type"] == "L4"
    assert plan["training_blocked"] is True
    assert plan["total_train_targets_validated"] == 10
    assert plan["selected_target_count"] == 4


def test_poc_train_grpo_fail_closed_when_training_blocked(monkeypatch):
    import modal_grpo_poc_app

    monkeypatch.delenv("TRAINING_STATUS", raising=False)
    monkeypatch.delenv("TRAINING_BLOCKED", raising=False)

    raw_train = getattr(modal_grpo_poc_app.poc_train_grpo, "local", modal_grpo_poc_app.poc_train_grpo)
    with pytest.raises(RuntimeError, match="TRAINING_STATUS = BLOCKED"):
        raw_train()


def test_modal_grpo_poc_app_ast_contract():
    src = (REPO_ROOT / "modal_grpo_poc_app.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    # Must never import modal_app
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "modal_app"
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "modal_app"

    gpu_fns = {"poc_collect_train_rollouts", "poc_diagnostic_grpo_forward", "poc_train_grpo"}
    found_fns = set()

    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in gpu_fns | {"poc_verify_train_exploit"}:
            found_fns.add(node.name)
            dec = node.decorator_list[0]
            assert isinstance(dec, ast.Call)
            kw_map = {kw.arg: kw.value for kw in dec.keywords if kw.arg is not None}

            if node.name == "poc_verify_train_exploit":
                assert isinstance(kw_map["block_network"], ast.Constant)
                assert kw_map["block_network"].value is True
            else:
                assert ast.unparse(kw_map["gpu"]) == "config.GRPO_POC_GPU_TYPE"
                assert ast.unparse(kw_map["min_containers"]) == "0"
                assert ast.unparse(kw_map["buffer_containers"]) == "0"
                assert ast.unparse(kw_map["scaledown_window"]) == "60"

    assert found_fns == gpu_fns | {"poc_verify_train_exploit"}


def test_modal_app_diagnostic_grpo_forward_and_scaledown_fixes():
    src = (REPO_ROOT / "modal_app.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    target_fns = {
        "diagnostic_grpo_forward_remote",
        "train_grpo_remote",
        "collect_train_rollouts_remote",
    }
    found = set()

    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in target_fns:
            found.add(node.name)
            dec = node.decorator_list[0]
            assert isinstance(dec, ast.Call)
            kw_map = {kw.arg: kw.value for kw in dec.keywords if kw.arg is not None}
            assert ast.unparse(kw_map["min_containers"]) == "0"
            assert ast.unparse(kw_map["buffer_containers"]) == "0"
            assert ast.unparse(kw_map["scaledown_window"]) == "60"

            if node.name == "diagnostic_grpo_forward_remote":
                fn_src = ast.get_source_segment(src, node)
                assert fn_src is not None
                reload_idx = fn_src.index("model_volume.reload()")
                tok_idx = fn_src.index("AutoTokenizer.from_pretrained")
                model_idx = fn_src.index("AutoModelForCausalLM.from_pretrained")
                assert reload_idx < tok_idx < model_idx
                assert "diagnose_group_spread(groups)" in fn_src
                assert '"group_spread": spread' in fn_src

    assert found == target_fns

    # Verify --mode diagnostic-forward in main() does not default to AUDIT_GPU_MODEL
    assert "diag_model_id = config.DEV_GPU_MODEL if generator.lower() == \"dev\" else config.GRPO_BASE_MODEL" in src


def test_run_grpo_poc_group_size_bounds():
    from benchmarks.run_grpo_poc import _validate_bounds, run_dry_run

    for bad_size in (2, 3):
        with pytest.raises(ValueError, match="group-size"):
            _validate_bounds(max_targets=4, group_size=bad_size, max_new_tokens=1536)
        with pytest.raises(ValueError, match="group-size"):
            run_dry_run(
                stage="collect-and-diagnose",
                max_targets=1,
                group_size=bad_size,
                max_new_tokens=1536,
                model_id="Qwen/Qwen2.5-Coder-1.5B-Instruct",
            )

    _validate_bounds(max_targets=4, group_size=4, max_new_tokens=1536)


def test_poc_collect_train_rollouts_mock_execution(monkeypatch):
    from unittest.mock import MagicMock

    import modal_grpo_poc_app
    from core.llm_generator import build_exploit_engineer_system_prompt, parse_model_response
    from core.schemas import TargetProgram
    from core.train_rollout_collector import TrainRolloutCollectionResult

    assert callable(build_exploit_engineer_system_prompt)
    assert callable(parse_model_response)

    # Mock container dataset path existence so _resolve_train_dataset_paths returns 4 Path objects
    orig_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self.as_posix() == "/opt/aegis/benchmarks/train_dataset.json":
            return True
        return orig_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    paths = modal_grpo_poc_app._resolve_train_dataset_paths()
    assert len(paths) == 4
    assert all(isinstance(p, Path) for p in paths)
    assert paths[2] == Path("/opt/aegis/benchmarks/targets/solidity_train")

    dummy_target = TargetProgram(
        name="TrainShareVault",
        source_code="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract TrainShareVault {}",
        invariants=["SOLVENCY"],
    )
    real_result = TrainRolloutCollectionResult(
        run_id="poc-test-run",
        trajectory_dir="/vol/models/trajectories_grpo_poc",
        targets_processed=1,
        candidates_generated=4,
        persisted_count=4,
        excluded_infra_count=0,
        excluded_missing_tokens_count=0,
        persisted_paths=["/vol/models/trajectories_grpo_poc/t1.json"],
        category_counts={"EXPLOIT_CONFIRMED": 1, "REVERTED": 3},
        group_spread={"total_groups": 1, "informative_groups": 1, "degenerate_groups": 0},
    )

    mock_tokenizer = MagicMock()
    mock_tokenizer.pad_token = "<eos>"
    mock_model = MagicMock()
    mock_model.to.return_value = mock_model

    with patch.object(modal_grpo_poc_app.model_volume, "reload"), \
         patch.object(modal_grpo_poc_app.model_volume, "commit"), \
         patch("core.train_rollout_collector.load_train_targets", return_value=[dummy_target]) as mock_load, \
         patch("core.train_rollout_collector.collect_train_rollouts", return_value=real_result) as mock_collect, \
         patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
         patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=mock_model):
        fn = getattr(
            modal_grpo_poc_app.poc_collect_train_rollouts,
            "local",
            modal_grpo_poc_app.poc_collect_train_rollouts,
        )
        out = fn(max_targets=1, group_size=4)

    mock_load.assert_called_once_with(
        train_dataset_path=Path("/opt/aegis/benchmarks/train_dataset.json"),
        benchmark_dataset_path=Path("/opt/aegis/benchmarks/benchmark_dataset.json"),
        train_solidity_dir=Path("/opt/aegis/benchmarks/targets/solidity_train"),
        test_solidity_dir=Path("/opt/aegis/benchmarks/targets/solidity"),
    )
    assert mock_collect.call_args.kwargs["benchmark_dataset_path"] == Path("/opt/aegis/benchmarks/benchmark_dataset.json")
    assert mock_collect.call_args.kwargs["test_solidity_dir"] == Path("/opt/aegis/benchmarks/targets/solidity")
    assert mock_collect.call_args.kwargs["model_id"] == "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    assert mock_collect.call_args.kwargs["run_id"].startswith("poc_run_")
    assert out["trajectory_dir"] == f"/vol/models/trajectories_grpo_poc/{out['run_id']}"

    assert out["status"] == "success"
    assert out["run_id"] == out["run_id"]
    assert out["gpu_type"] == "L4"
    assert out["persisted_count"] == 4
    assert out["excluded_infra_count"] == 0
    assert out["category_counts"] == {"EXPLOIT_CONFIRMED": 1, "REVERTED": 3}
    assert out["group_spread"] == {"total_groups": 1, "informative_groups": 1, "degenerate_groups": 0}


def _make_dummy_grpo_group():
    from core.schemas import AttackHypothesis, GRPOGroup, GRPORollout, ResultCategory

    hyp = AttackHypothesis(
        vulnerability_type="Reentrancy",
        reasoning_trace="trace",
        attack_vector="withdraw()",
    )
    rollouts = [
        GRPORollout(
            candidate_id=f"cand-{i}",
            hypothesis=hyp,
            full_completion_text=f"exploit-{i}",
            exploit_code=f"exploit-{i}",
            reward=1.0 if i == 0 else -0.25,
            category=ResultCategory.EXPLOIT_CONFIRMED if i == 0 else ResultCategory.RUNTIME_REVERT,
            is_verified=(i == 0),
            reproduced=(i == 0),
            feedback="ok",
            advantage=1.5 if i == 0 else -0.5,
            generated_token_ids=[10, 11, 12],
            reward_spec_version="2.0.0",
        )
        for i in range(4)
    ]
    return GRPOGroup(
        group_id="grp-1",
        target_name="TrainShareVault",
        prompt="prompt-text",
        system_prompt="sys-prompt",
        rollouts=rollouts,
        mean_reward=0.0625,
        std_reward=0.54,
        reward_spec_version="2.0.0",
    )


def test_poc_diagnostic_grpo_forward_happy_and_empty_paths():
    import math
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import torch

    import modal_grpo_poc_app

    group = _make_dummy_grpo_group()
    inp_ids = torch.tensor([[1, 2, 3, 4, 5]], dtype=torch.long)
    att_mask = torch.ones_like(inp_ids)
    comp_mask = torch.tensor([[0, 0, 1, 1, 1]], dtype=torch.float32)

    class _StubModel:
        device = "cpu"

        def eval(self):
            return self

        def __call__(self, input_ids, attention_mask=None):
            batch, seq_len = input_ids.shape
            logits = torch.zeros((batch, seq_len, 16), dtype=torch.float32)
            return SimpleNamespace(logits=logits)

    mock_tokenizer = MagicMock()
    mock_tokenizer.pad_token = "<eos>"
    stub_model = _StubModel()

    fn = getattr(
        modal_grpo_poc_app.poc_diagnostic_grpo_forward,
        "local",
        modal_grpo_poc_app.poc_diagnostic_grpo_forward,
    )

    with patch.object(modal_grpo_poc_app.model_volume, "reload"), \
         patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
         patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=stub_model), \
         patch("core.grpo_trainer.load_production_trajectories", return_value=[{"id": 1}]), \
         patch("core.grpo_trainer.group_rollouts_by_prompt", return_value=[group]), \
         patch("core.grpo_trainer.prepare_rollout_tokens", return_value=(inp_ids, att_mask, comp_mask)) as mock_prep:
        res = fn(batch_group_size=4)

    from core.config import config

    assert mock_prep.call_count == 4
    mock_prep.assert_any_call(
        "prompt-text",
        "exploit-0",
        mock_tokenizer,
        max_seq_len=config.GRPO_MAX_SEQ_LEN,
        device="cuda",
        stored_generated_token_ids=[10, 11, 12],
    )
    assert res["status"] == "SUCCESS"
    assert res["gpu_type"] == "L4"
    assert res["skipped_overlength_count"] == 0
    assert math.isfinite(res["diagnostic_loss"])
    assert res["group_spread"]["informative_groups"] == 1
    assert res["optimizer_step_executed"] is False
    assert res["weights_updated"] is False
    assert res["checkpoints_created"] is False

    # All rollouts unsafe/overlength -> ALL_ROLLOUTS_UNSAFE
    from core.grpo_trainer import UnsafeRolloutError

    with patch.object(modal_grpo_poc_app.model_volume, "reload"), \
         patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
         patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=stub_model), \
         patch("core.grpo_trainer.load_production_trajectories", return_value=[{"id": 1}]), \
         patch("core.grpo_trainer.group_rollouts_by_prompt", return_value=[group]), \
         patch("core.grpo_trainer.prepare_rollout_tokens", side_effect=UnsafeRolloutError("too long")):
        unsafe_res = fn(batch_group_size=4)

    assert unsafe_res["status"] == "ALL_ROLLOUTS_UNSAFE"
    assert unsafe_res["skipped_overlength_count"] == 4
    assert unsafe_res["optimizer_step_executed"] is False

    # Empty-path: 0 trajectories -> NO_PRODUCTION_TRAJECTORIES
    with patch.object(modal_grpo_poc_app.model_volume, "reload"), \
         patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
         patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=stub_model), \
         patch("core.grpo_trainer.load_production_trajectories", return_value=[]):
        empty_res = fn(batch_group_size=4)

    assert empty_res["status"] == "NO_PRODUCTION_TRAJECTORIES"
    assert empty_res["eligible_count"] == 0


def test_poc_train_grpo_unblocked_happy_path(monkeypatch):
    from unittest.mock import MagicMock

    import torch

    import modal_grpo_poc_app
    from core.schemas import GRPOTrainingStepStats

    monkeypatch.setattr(modal_grpo_poc_app, "is_training_blocked", lambda _cfg: False)

    group = _make_dummy_grpo_group()
    step_stats = [
        GRPOTrainingStepStats(
            step=1,
            loss=0.42,
            mean_reward=0.0625,
            mean_advantage=0.0,
            kl_divergence=0.01,
            learning_rate=5e-6,
        ),
        GRPOTrainingStepStats(
            step=2,
            loss=0.31,
            mean_reward=0.125,
            mean_advantage=0.0,
            kl_divergence=0.02,
            learning_rate=5e-6,
        ),
    ]

    tiny_linear = torch.nn.Linear(4, 4)
    mock_tokenizer = MagicMock()
    mock_tokenizer.pad_token = "<eos>"
    mock_base_model = MagicMock()
    mock_base_model.to.return_value = mock_base_model

    fn = getattr(
        modal_grpo_poc_app.poc_train_grpo,
        "local",
        modal_grpo_poc_app.poc_train_grpo,
    )

    with patch.object(modal_grpo_poc_app.model_volume, "reload"), \
         patch.object(modal_grpo_poc_app.model_volume, "commit") as mock_commit, \
         patch("core.grpo_trainer.load_production_trajectories", return_value=[{"id": 1}]), \
         patch("core.grpo_trainer.group_rollouts_by_prompt", return_value=[group]), \
         patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
         patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=mock_base_model), \
         patch("core.grpo_trainer.setup_lora_model", return_value=tiny_linear), \
         patch("core.grpo_trainer.train_grpo_epochs", return_value=step_stats), \
         patch("core.grpo_trainer.save_lora_checkpoint", return_value="/vol/models/checkpoints_grpo_poc/step_2"):
        out = fn(num_steps=2, batch_group_size=4)

    mock_commit.assert_called_once()
    assert out["status"] == "success"
    assert out["gpu_type"] == "L4"
    assert out["steps_completed"] == 2
    assert out["checkpoint_path"] == "/vol/models/checkpoints_grpo_poc/step_2"
    assert len(out["logs"]) == 2
    assert out["logs"][0]["step"] == 1
    assert out["logs"][1]["loss"] == 0.31


def test_run_live_poc_collect_and_diagnose_with_mock_modal(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from benchmarks.run_grpo_poc import APPROVAL_ENV_VAR, run_live_poc

    monkeypatch.setenv(APPROVAL_ENV_VAR, "1")

    collect_remote = MagicMock(
        return_value={
            "status": "success",
            "run_id": "poc_run_abc123",
            "trajectory_dir": "/vol/models/trajectories_grpo_poc/poc_run_abc123",
            "persisted_count": 16,
        }
    )
    diag_remote = MagicMock(return_value={"status": "SUCCESS", "diagnostic_loss": 1.23})
    mapping = {
        ("aegis-rlvr-grpo-poc", "poc_collect_train_rollouts"): SimpleNamespace(remote=collect_remote),
        ("aegis-rlvr-grpo-poc", "poc_diagnostic_grpo_forward"): SimpleNamespace(remote=diag_remote),
    }

    from_name_mock = MagicMock(side_effect=lambda app_name, fn_name: mapping[(app_name, fn_name)])
    fake_modal = SimpleNamespace(Function=SimpleNamespace(from_name=from_name_mock))

    with patch.dict(sys.modules, {"modal": fake_modal}):
        res = run_live_poc(
            stage="collect-and-diagnose",
            max_targets=4,
            group_size=4,
            output_dir=str(tmp_path),
            target_names="TrainPushAuction,TrainRewardPool",
            run_id="poc_run_abc123",
        )

    from_name_mock.assert_any_call("aegis-rlvr-grpo-poc", "poc_collect_train_rollouts")
    from_name_mock.assert_any_call("aegis-rlvr-grpo-poc", "poc_diagnostic_grpo_forward")
    collect_remote.assert_called_once()
    assert collect_remote.call_args.kwargs["target_names"] == ["TrainPushAuction", "TrainRewardPool"]
    assert collect_remote.call_args.kwargs["run_id"] == "poc_run_abc123"
    diag_remote.assert_called_once()
    assert diag_remote.call_args.kwargs["trajectory_dir"] == "/vol/models/trajectories_grpo_poc/poc_run_abc123"
    assert res["trajectory_dir"] == "/vol/models/trajectories_grpo_poc/poc_run_abc123"
    assert res["collect"]["persisted_count"] == 16
    assert res["diagnose"]["diagnostic_loss"] == 1.23

    artifact_path = Path(res["artifact_file"])
    assert artifact_path.exists()
    assert artifact_path.parent == tmp_path
    loaded = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert loaded["stage"] == "collect-and-diagnose"


def test_run_grpo_poc_target_names_and_cli_flags(capsys):
    from benchmarks.run_grpo_poc import main, run_dry_run

    with pytest.raises(ValueError, match="Unknown or non-train target_names"):
        run_dry_run(
            stage="collect",
            max_targets=4,
            group_size=4,
            max_new_tokens=1536,
            model_id="Qwen/Qwen2.5-Coder-1.5B-Instruct",
            target_names="Vault",
        )

    with pytest.raises(ValueError, match="Unknown or non-train target_names"):
        run_dry_run(
            stage="collect",
            max_targets=4,
            group_size=4,
            max_new_tokens=1536,
            model_id="Qwen/Qwen2.5-Coder-1.5B-Instruct",
            target_names="NonExistentContract",
        )

    with patch.dict(sys.modules, {"modal": None}):
        code = main([
            "--dry-run",
            "--target-names", "TrainPushAuction,TrainAdminTreasury",
            "--run-id", "poc_run_custom",
            "--num-steps", "3",
            "--learning-rate", "1e-5",
        ])
    assert code == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["selected_targets"] == ["TrainPushAuction", "TrainAdminTreasury"]
    assert plan["selected_target_count"] == 2
    assert plan["run_id"] == "poc_run_custom"
    assert plan["trajectory_dir"] == "/vol/models/trajectories_grpo_poc/poc_run_custom"
    assert plan["num_steps"] == 3
    assert plan["learning_rate"] == 1e-5


def test_poc_collect_skips_remote_verifier_on_invalid_format_and_propagates_commit_error():
    from unittest.mock import MagicMock

    import modal_grpo_poc_app
    from core.schemas import AttackHypothesis, ExploitPayload, ResultCategory, TargetProgram

    dummy_target = TargetProgram(
        name="TrainShareVault",
        source_code="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract TrainShareVault {}",
        invariants=["SOLVENCY"],
    )
    mock_tokenizer = MagicMock()
    mock_tokenizer.pad_token = "<eos>"
    mock_model = MagicMock()
    mock_model.to.return_value = mock_model

    captured_verifier = {}

    def fake_collect(**kwargs):
        captured_verifier["fn"] = kwargs["verifier_fn"]
        bad_payload = ExploitPayload(
            target_name=dummy_target.name,
            hypothesis=AttackHypothesis(
                vulnerability_type="Reentrancy",
                reasoning_trace="bad",
                attack_vector="none",
            ),
            test_code="",
            format_valid=False,
            format_error_reason="missing solidity block",
            generated_token_ids=[1, 2],
        )
        res = kwargs["verifier_fn"](dummy_target, bad_payload)
        assert res.category == ResultCategory.GENERATION_FORMAT_ERROR
        assert res.return_code == -4
        raise RuntimeError("stop_after_check")

    fn = getattr(
        modal_grpo_poc_app.poc_collect_train_rollouts,
        "local",
        modal_grpo_poc_app.poc_collect_train_rollouts,
    )

    with patch.object(modal_grpo_poc_app.model_volume, "reload"), \
         patch.object(modal_grpo_poc_app.poc_verify_train_exploit, "remote") as mock_remote, \
         patch("core.train_rollout_collector.load_train_targets", return_value=[dummy_target]), \
         patch("core.train_rollout_collector.collect_train_rollouts", side_effect=fake_collect), \
         patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
         patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=mock_model):
        with pytest.raises(RuntimeError, match="stop_after_check"):
            fn(target_names=["TrainShareVault"])

    mock_remote.assert_not_called()

    # Verify model_volume.commit() failure is NOT swallowed
    from core.train_rollout_collector import TrainRolloutCollectionResult

    ok_result = TrainRolloutCollectionResult(
        run_id="poc_run_commit_err",
        trajectory_dir="/vol/models/trajectories_grpo_poc/poc_run_commit_err",
        targets_processed=1,
        candidates_generated=4,
        persisted_count=4,
        excluded_infra_count=0,
        excluded_missing_tokens_count=0,
    )
    with patch.object(modal_grpo_poc_app.model_volume, "reload"), \
         patch.object(modal_grpo_poc_app.model_volume, "commit", side_effect=OSError("volume commit failed")), \
         patch("core.train_rollout_collector.load_train_targets", return_value=[dummy_target]), \
         patch("core.train_rollout_collector.collect_train_rollouts", return_value=ok_result), \
         patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
         patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=mock_model):
        with pytest.raises(OSError, match="volume commit failed"):
            fn(target_names=["TrainShareVault"])


def test_run_live_poc_train_forwards_unblock_secrets_and_remains_fail_closed(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from benchmarks.run_grpo_poc import APPROVAL_ENV_VAR, run_live_poc

    monkeypatch.setenv(APPROVAL_ENV_VAR, "1")
    monkeypatch.delenv("TRAINING_STATUS", raising=False)
    monkeypatch.delenv("TRAINING_BLOCKED", raising=False)

    # Without unblock env vars, --stage train must remain fail-closed before touching Modal.
    with patch.dict(sys.modules, {"modal": None}):
        with pytest.raises(RuntimeError, match="TRAINING_STATUS = BLOCKED"):
            run_live_poc(stage="train", output_dir=str(tmp_path))

    # With TRAINING_STATUS=UNBLOCKED and TRAINING_BLOCKED=false, secrets are forwarded via with_options.
    monkeypatch.setenv("TRAINING_STATUS", "UNBLOCKED")
    monkeypatch.setenv("TRAINING_BLOCKED", "false")

    train_remote = MagicMock(
        return_value={
            "status": "success",
            "steps_completed": 1,
            "checkpoint_path": "/vol/models/checkpoints_grpo_poc/step_1",
            "logs": [{"step": 1, "loss": 0.12, "kl_divergence": 0.01}],
        }
    )
    wrapped_fn = SimpleNamespace(remote=train_remote)
    with_options_mock = MagicMock(return_value=wrapped_fn)
    base_train_fn = SimpleNamespace(
        with_options=with_options_mock,
        remote=MagicMock(side_effect=AssertionError("expected wrapped train_fn.remote to be called")),
    )
    from_name_mock = MagicMock(return_value=base_train_fn)
    from_dict_mock = MagicMock(side_effect=lambda d: {"secret_dict": d})
    fake_modal = SimpleNamespace(
        Function=SimpleNamespace(from_name=from_name_mock),
        Secret=SimpleNamespace(from_dict=from_dict_mock),
    )

    with patch.dict(sys.modules, {"modal": fake_modal}):
        res = run_live_poc(
            stage="train",
            num_steps=1,
            group_size=4,
            run_id="poc_run_7543d0db",
            output_dir=str(tmp_path),
        )

    from_name_mock.assert_called_once_with("aegis-rlvr-grpo-poc", "poc_train_grpo")
    from_dict_mock.assert_called_once_with(
        {"TRAINING_STATUS": "UNBLOCKED", "TRAINING_BLOCKED": "false"}
    )
    with_options_mock.assert_called_once_with(
        secrets=[{"secret_dict": {"TRAINING_STATUS": "UNBLOCKED", "TRAINING_BLOCKED": "false"}}]
    )
    train_remote.assert_called_once()
    assert train_remote.call_args.kwargs["num_steps"] == 1
    assert res["train"]["status"] == "success"
    assert res["train"]["steps_completed"] == 1

