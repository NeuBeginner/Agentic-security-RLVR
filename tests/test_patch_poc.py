"""
tests/test_patch_poc.py
=======================

Unit tests for `core/patch_generator.py`, `benchmarks/run_patch_poc.py`,
and Modal PoC dual-loop wrappers in `modal_grpo_poc_app.py` (all mocked, $0.00).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from core.patch_generator import (
    MAX_SANDBOX_FEEDBACK_CHARS,
    build_patch_prompt,
    build_patch_refinement_prompt,
    build_patch_system_prompt,
    collect_blue_patch_rollouts,
    load_confirmed_red_exploits_from_dirs,
    parse_patch_response,
)
from core.patch_verifier import BluePatchCategory, PatchVerificationResult, compute_blue_reward_breakdown
from core.schemas import ExecutionResult, ResultCategory, TargetProgram
from sandbox.patch_runner import PatchSandboxResult


def test_parse_patch_response_extracts_fenced_and_fallback():
    raw_fenced = (
        "Here is the fix:\n```solidity\n// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\ncontract TrainAdminTreasury { address public governance; }\n```\n"
    )
    cand = parse_patch_response(raw_fenced, "TrainAdminTreasury", candidate_id="c0")
    assert cand.target_name == "TrainAdminTreasury"
    assert "contract TrainAdminTreasury" in cand.patched_source
    assert "```" not in cand.patched_source

    raw_plain = "Explanation...\n// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract TrainAdminTreasury {}"
    cand2 = parse_patch_response(raw_plain, "TrainAdminTreasury")
    assert cand2.patched_source.startswith("// SPDX-License-Identifier: MIT")


def test_build_patch_refinement_prompt_bounds_feedback():
    tgt = TargetProgram(name="TrainAdminTreasury", source_code="contract TrainAdminTreasury {}", language="solidity")
    ver_res = PatchVerificationResult(
        target_name="TrainAdminTreasury",
        category=BluePatchCategory.FUNCTIONAL_REGRESSION,
        reward_score=-0.25,
        compiled=True,
        functional_pass=False,
        reason="functional failed",
        reward_breakdown=compute_blue_reward_breakdown(BluePatchCategory.FUNCTIONAL_REGRESSION, compiled=True),
    )
    long_fb = "X" * 3000
    prompt = build_patch_refinement_prompt(
        target=tgt,
        red_exploit_code="contract ExploitModule {}",
        failed_patch="contract TrainAdminTreasury { /* bad */ }",
        verification_result=ver_res,
        sandbox_feedback=long_fb,
    )
    assert "FUNCTIONAL_REGRESSION" in prompt
    assert "X" * MAX_SANDBOX_FEEDBACK_CHARS in prompt
    assert "X" * (MAX_SANDBOX_FEEDBACK_CHARS + 1) not in prompt
    assert "Minimal" in build_patch_system_prompt() or "minimal" in build_patch_system_prompt()
    assert "TrainAdminTreasury" in build_patch_prompt(tgt, "contract ExploitModule {}")


def test_load_confirmed_red_exploits_from_dirs(tmp_path):
    d1 = tmp_path / "dir1"
    d1.mkdir()
    (d1 / "t1.json").write_text(
        json.dumps({"target_name": "TrainAdminTreasury", "category": "RUNTIME_REVERT", "exploit_code": "bad"}),
        encoding="utf-8",
    )
    (d1 / "t2.json").write_text(
        json.dumps({"target_name": "TrainAdminTreasury", "category": "EXPLOIT_CONFIRMED", "exploit_code": "contract ExploitModule { /* ok */ }", "trajectory_id": "traj_123"}),
        encoding="utf-8",
    )
    found = load_confirmed_red_exploits_from_dirs([str(d1)], ["TrainAdminTreasury", "TrainShareVault"])
    assert "TrainAdminTreasury" in found
    assert found["TrainAdminTreasury"]["trajectory_id"] == "traj_123"
    assert "TrainShareVault" not in found


def test_load_confirmed_red_exploits_from_real_rlvr_trajectory_schema(tmp_path):
    """Regression: RLVRTrajectory.model_dump() stores exploit code in `generated_exploit`, not `exploit_code`."""
    from core.schemas import AttackHypothesis, RLVRTrajectory

    d = tmp_path / "traj_dir"
    d.mkdir()
    traj = RLVRTrajectory(
        trajectory_id="traj_real_schema_01",
        candidate_id="cand_01",
        target_name="TrainShareVault",
        target_code="contract TrainShareVault {}",
        hypothesis=AttackHypothesis(
            vulnerability_type="share_inflation",
            reasoning_trace="reasoning",
            attack_vector="deposit 1 wei",
        ),
        prompt_hash="abc123",
        generated_exploit="contract ExploitModule { function runExploit() external payable {} }",
        category=ResultCategory.EXPLOIT_CONFIRMED,
        reward=1.0,
        invariant_violated=True,
        is_verified=True,
        reproduced=True,
        replay_status="CONFIRMED",
        feedback_trace="EXPLOIT_CONFIRMED",
    )
    dumped = traj.model_dump(mode="json")
    assert "exploit_code" not in dumped
    assert "generated_exploit" in dumped
    (d / "traj_real_schema_01.json").write_text(json.dumps(dumped), encoding="utf-8")

    found = load_confirmed_red_exploits_from_dirs([str(d)], ["TrainShareVault"])
    assert "TrainShareVault" in found
    assert found["TrainShareVault"]["trajectory_id"] == "traj_real_schema_01"
    assert "contract ExploitModule" in found["TrainShareVault"]["exploit_code"]


def test_collect_blue_patch_rollouts_early_stop_and_honest_refinement(tmp_path):
    tgt = TargetProgram(
        name="TrainAdminTreasury",
        source_code="contract TrainAdminTreasury { address public governance; }",
        language="solidity",
    )
    red_exploits = {
        "TrainAdminTreasury": {"exploit_code": "contract ExploitModule {}", "trajectory_id": "traj_red_1"}
    }

    calls = {"gen": 0}

    def mock_gen(t, prompt, temp, cand_idx):
        calls["gen"] += 1
        if "FOUNDRY VERIFIER FEEDBACK" in prompt:
            return "```solidity\ncontract TrainAdminTreasury { address public governance; /* good */ }\n```"
        return "```solidity\ncontract TrainAdminTreasury { address public governance; /* bad */ }\n```"

    def mock_red_verifier(t, p):
        return ExecutionResult(
            return_code=0,
            stdout="",
            stderr="",
            execution_time_sec=0.1,
            category=ResultCategory.EXPLOIT_CONFIRMED,
            invariant_violated=True,
            test_status="Success",
        )

    def mock_patch_runner(tname, psrc, ecode):
        if "/* good */" in psrc:
            return PatchSandboxResult(target_name=tname, compiled=True, functional_pass=True, exploit_blocked=True)
        return PatchSandboxResult(
            target_name=tname,
            compiled=True,
            functional_pass=False,
            exploit_blocked=True,
            functional_stderr="Assertion failed: governance not updated",
        )

    summary = collect_blue_patch_rollouts(
        targets=[tgt],
        red_exploits=red_exploits,
        output_dir=str(tmp_path / "out"),
        generator_fn=mock_gen,
        red_verifier=mock_red_verifier,
        patch_runner=mock_patch_runner,
        group_size=4,
        max_refinement_rounds=1,
        run_id="dual_test",
    )
    # Early-stop on candidate 0 after Round 1 achieves PATCH_VERIFIED (+1.0)
    assert summary["persisted_count"] == 1
    assert summary["verified_targets"] == ["TrainAdminTreasury"]
    assert summary["improved_by_refinement_count"] == 1
    assert summary["mean_blue_reward"] == 1.0
    assert calls["gen"] == 2

    # When refinement does NOT improve, improved_by_refinement_count must stay strictly 0
    summary_no_imp = collect_blue_patch_rollouts(
        targets=[tgt],
        red_exploits=red_exploits,
        output_dir=str(tmp_path / "out2"),
        generator_fn=lambda t, p, temp, idx: "```solidity\ncontract TrainAdminTreasury { address public governance; /* bad */ }\n```",
        red_verifier=mock_red_verifier,
        patch_runner=mock_patch_runner,
        group_size=2,
        max_refinement_rounds=1,
        run_id="dual_no_imp",
    )
    assert summary_no_imp["persisted_count"] == 2
    assert summary_no_imp["improved_by_refinement_count"] == 0
    assert summary_no_imp["mean_blue_reward"] == -0.25


def test_run_patch_poc_dry_run_and_fail_closed(monkeypatch, tmp_path):
    import benchmarks.run_patch_poc as driver

    plan = driver.run_dry_run(
        run_id="dual_loop_poc_3t",
        target_names="TrainAdminTreasury,TrainShareVault,TrainUninitializedVault",
        group_size=4,
        max_refinement_rounds=1,
    )
    assert plan["mode"] == "dry-run"
    assert plan["cost_usd"] == 0.0
    assert len(plan["target_names"]) == 3

    with pytest.raises(ValueError, match="functional regression suites"):
        driver.run_dry_run(target_names="UnknownContract")
    with pytest.raises(ValueError, match="--group-size"):
        driver.run_dry_run(group_size=5)

    monkeypatch.delenv("AEGIS_APPROVE_GRPO_POC", raising=False)
    with pytest.raises(PermissionError, match="AEGIS_APPROVE_GRPO_POC=1"):
        driver.run_live_patch_poc()

    monkeypatch.setenv("AEGIS_APPROVE_GRPO_POC", "1")
    remote_mock = MagicMock(return_value={"status": "success", "verified_targets": ["TrainAdminTreasury"]})
    with patch("modal.Function.from_name", return_value=SimpleNamespace(remote=remote_mock)):
        res = driver.run_live_patch_poc(run_id="dual_mock", output_dir=str(tmp_path))
    assert res["status"] == "success"
    assert Path(res["artifact_file"]).is_file()


def test_modal_poc_verify_train_patch_and_dual_loop_mock(tmp_path):
    import modal_grpo_poc_app

    verify_fn = getattr(modal_grpo_poc_app.poc_verify_train_patch, "local", modal_grpo_poc_app.poc_verify_train_patch)
    fake_sb = PatchSandboxResult(target_name="TrainAdminTreasury", compiled=True, functional_pass=True, exploit_blocked=True)
    with patch("modal_grpo_poc_app.run_patch_in_sandbox", return_value=fake_sb):
        out = verify_fn("TrainAdminTreasury", "contract TrainAdminTreasury {}", "contract ExploitModule {}")
    assert out["compiled"] is True
    assert out["exploit_blocked"] is True
