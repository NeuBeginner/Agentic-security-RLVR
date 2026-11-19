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

    assert out["status"] == "success"
    assert out["run_id"] == "poc-test-run"
    assert out["gpu_type"] == "L4"
    assert out["persisted_count"] == 4
    assert out["excluded_infra_count"] == 0
    assert out["category_counts"] == {"EXPLOIT_CONFIRMED": 1, "REVERTED": 3}
    assert out["group_spread"] == {"total_groups": 1, "informative_groups": 1, "degenerate_groups": 0}
