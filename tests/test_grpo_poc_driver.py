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
