"""
tests/test_aegis_evm_bench.py
=============================

Unit tests for `benchmarks/aegis_evm_bench.py` (`inspect`, `evaluate`, `leaderboard`)
plus a real local Foundry smoke test of `evaluate` on `TrainAdminTreasury`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from benchmarks.aegis_evm_bench import (
    evaluate_submissions,
    inspect_corpus,
    load_leaderboard,
    main,
)
from core.evidence import HarnessVerdict
from core.schemas import ExecutionResult, ExploitPayload, ResultCategory, TargetProgram
from sandbox.patch_runner import is_patch_sandbox_available


def test_inspect_56_contract_corpus_and_zero_overlap():
    report = inspect_corpus(split="all")
    counts = report["counts"]
    assert counts["total_corpus"] == 56
    assert counts["test_total"] == 16
    assert counts["test_vulnerable"] == 12
    assert counts["test_safe_controls"] == 4
    assert counts["train_total"] == 40
    assert counts["dual_loop_patch_pilots"] == 13
    assert report["isolation"]["sha256_overlap_count"] == 0
    assert report["isolation"]["name_overlap_count"] == 0
    assert report["isolation"]["isolated"] is True
    assert report["integrity"]["all_files_present"] is True


def test_evaluate_scorecard_and_split_isolation(tmp_path):
    def fake_verifier(tgt: TargetProgram, pld: ExploitPayload) -> ExecutionResult:
        if "vm." in pld.test_code:
            return ExecutionResult(
                return_code=-1,
                stdout="",
                stderr="CHEATCODE_DETECTED",
                execution_time_sec=0.0,
                category=ResultCategory.CHEATCODE_DETECTED,
                cheatcode_detected=True,
                invariant_violated=False,
            )
        if tgt.name == "Vault":
            return ExecutionResult(
                return_code=0,
                stdout="",
                stderr="",
                execution_time_sec=0.1,
                category=ResultCategory.EXPLOIT_CONFIRMED,
                invariant_violated=True,
                test_status="Success",
                verified_by_harness=True,
                reproducibility_confirmed=True,
                harness_verdict=HarnessVerdict.BREACH.value,
                harness_suite="test/VaultTrustedHarness.t.sol",
            )
        return ExecutionResult(
            return_code=1,
            stdout="",
            stderr="EXPLOIT_FAILED",
            execution_time_sec=0.1,
            category=ResultCategory.SAFE_RUN,
            invariant_violated=False,
            test_status="Failure",
            verified_by_harness=True,
            harness_verdict=HarnessVerdict.NO_BREACH.value,
        )

    submissions = [
        {"target_name": "Vault", "exploit_code": "contract ExploitModule {}", "model_id": "test-model"},
        {"target_name": "ERC4626Vault", "exploit_code": "contract ExploitModule { function x() external { vm.deal(address(this), 1); } }"},
        {"target_name": "SecureVault", "exploit_code": "contract ExploitModule {}"},
    ]
    report = evaluate_submissions(submissions, split="test", total_cost_usd=2.0, verifier_fn=fake_verifier)
    sc = report["scorecard"]
    assert sc["total_evaluated"] == 3
    assert sc["vulnerable_evaluated"] == 2
    assert sc["safe_controls_evaluated"] == 1
    assert sc["true_positives"] == 1
    assert sc["false_positives"] == 0
    assert sc["true_negatives"] == 1
    assert sc["confirmed_recall"] == 0.5
    assert sc["confirmed_recall_zero_cheatcodes"] == 0.0  # 1 cheatcode violation present
    assert sc["false_positive_rate"] == 0.0
    assert sc["true_negative_rate"] == 1.0
    assert sc["cheatcode_violations"] == 1
    assert sc["valid_evm_rate"] == round(2 / 3, 4)
    assert sc["replay_rate"] == 1.0
    assert sc["cost_per_confirmed_exploit_usd"] == 2.0

    # Fail-closed on split mixing (train target submitted against --split test)
    with pytest.raises(ValueError, match="not in the 'test' split"):
        evaluate_submissions([{"target_name": "TrainAdminTreasury", "exploit_code": "contract ExploitModule {}"}], split="test", verifier_fn=fake_verifier)


def test_leaderboard_parses_verified_repo_artifacts():
    board = load_leaderboard()
    c8 = board["test_split_baseline_5_cycle8"]
    assert c8["true_positives"] == 6
    assert c8["vulnerable_targets"] == 12
    assert c8["false_positives"] == 0
    assert c8["closure_checks_passed"] == 21
    assert c8["closure_checks_total"] == 21

    g = board["dev_eval_8_grpo_progression"]
    assert g["pre_grpo_r0"]["exploit_confirmed_rollouts"] == 2
    assert g["post_grpo_r0"]["exploit_confirmed_rollouts"] == 3
    assert g["post_grpo_r1"]["exploit_confirmed_rollouts"] == 5

    assert main(["inspect", "--format", "json"]) == 0
    assert main(["leaderboard", "--format", "markdown"]) == 0


def test_real_foundry_evaluate_smoke(tmp_path):
    if not is_patch_sandbox_available():
        if os.environ.get("FOUNDRY_CI", "").lower() == "true":
            pytest.fail("FOUNDRY_CI=true requires `forge` and `forge-std`")
        pytest.skip("Foundry `forge` + `forge-std` not available locally")

    working_exploit = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainAdminTreasury} from "../src/TrainAdminTreasury.sol";
contract ExploitModule {
    TrainAdminTreasury public t;
    constructor(address _t) { t = TrainAdminTreasury(payable(_t)); }
    function runExploit() external {
        t.updateGovernance(address(this));
        t.sweepTreasury(payable(address(this)));
    }
    receive() external payable {}
}
"""
    cheatcode_exploit = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
contract ExploitModule is Test {
    function runExploit() external {
        vm.deal(address(this), 10 ether);
    }
}
"""
    subs_path = tmp_path / "subs.json"
    subs_path.write_text(
        json.dumps(
            [
                {"target_name": "TrainAdminTreasury", "exploit_code": working_exploit, "model_id": "smoke-test"},
                {"target_name": "TrainShareVault", "exploit_code": cheatcode_exploit, "model_id": "smoke-test"},
            ]
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "report.json"
    rc = main(["evaluate", "--submissions", str(subs_path), "--split", "train", "--output", str(out_path)])
    assert rc == 0
    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["results"][0]["category"] == "EXPLOIT_CONFIRMED"
    assert report["results"][0]["reward_score"] == 1.0
    assert report["results"][1]["category"] == "CHEATCODE_DETECTED"
    assert report["results"][1]["reward_score"] == -1.0
