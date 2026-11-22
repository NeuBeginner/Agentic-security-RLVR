"""
tests/test_patch_verifier.py
============================

Unit tests (mocked, all 8 BluePatchCategory outcomes + fail-closed gates) and
real Foundry integration tests across the 5 pilot Dual-Loop contracts × 4 scenarios.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import pytest

from core.patch_verifier import (
    BLUE_REWARD_SPEC_VERSION,
    BLUE_REWARD_TABLE,
    BluePatchCategory,
    DualLoopRecord,
    PatchCandidate,
    compute_blue_reward_breakdown,
    verify_patch,
)
from core.schemas import (
    AttackHypothesis,
    ExecutionResult,
    ExploitPayload,
    ResultCategory,
    TargetProgram,
)
from sandbox.patch_runner import (
    LOCAL_TRAIN_FUNCTIONAL_TESTS_DIR,
    TRAIN_FUNCTIONAL_TESTS,
    PatchSandboxResult,
    is_patch_sandbox_available,
)
from sandbox.runner import LOCAL_TRAIN_HARNESSES_DIR, run_payload_in_sandbox

SOLIDITY_TRAIN_DIR = Path(LOCAL_TRAIN_HARNESSES_DIR)


def _ok_red_verifier(tgt: TargetProgram, pld: ExploitPayload) -> ExecutionResult:
    return ExecutionResult(
        return_code=0,
        stdout="",
        stderr="",
        execution_time_sec=0.1,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        invariant_violated=True,
        test_status="Success",
    )


def _fail_red_verifier(tgt: TargetProgram, pld: ExploitPayload) -> ExecutionResult:
    return ExecutionResult(
        return_code=1,
        stdout="",
        stderr="EXPLOIT_FAILED",
        execution_time_sec=0.1,
        category=ResultCategory.RUNTIME_REVERT,
        invariant_violated=False,
    )


# ---------------------------------------------------------------------------
# Fast unit tests (all 8 categories & fail-closed gates)
# ---------------------------------------------------------------------------


def test_blue_reward_table_covers_all_categories():
    assert set(BLUE_REWARD_TABLE.keys()) == set(BluePatchCategory)
    for cat in BluePatchCategory:
        bd = compute_blue_reward_breakdown(cat)
        assert bd.spec_version == BLUE_REWARD_SPEC_VERSION
        assert bd.reward_score == BLUE_REWARD_TABLE[cat]
        assert bd.trainable is (cat != BluePatchCategory.PATCH_INFRA_ERROR)


def test_static_gates_cheatcode_and_noop_and_missing_contract():
    orig = "contract TrainAdminTreasury { function f() external {} }"
    exploit = "contract ExploitModule { function runExploit() external {} }"

    # 1. Cheatcode violation -> -1.0
    for bad in (
        "import \"forge-std/Test.sol\"; contract TrainAdminTreasury {}",
        "contract TrainAdminTreasury { function f() external { vm.prank(address(0)); } }",
        "contract TrainAdminTreasury { function f() external { selfdestruct(payable(msg.sender)); } }",
    ):
        res = verify_patch(
            target_name="TrainAdminTreasury",
            original_source=orig,
            candidate=PatchCandidate(target_name="TrainAdminTreasury", patched_source=bad),
            exploit_code=exploit,
            red_verifier=_ok_red_verifier,
        )
        assert res.category == BluePatchCategory.PATCH_CHEATCODE_VIOLATION
        assert res.reward_score == -1.0

    # 2. Missing contract declaration -> PATCH_FORMAT_ERROR (-0.35)
    res_missing = verify_patch(
        target_name="TrainAdminTreasury",
        original_source=orig,
        candidate=PatchCandidate(target_name="TrainAdminTreasury", patched_source="contract WrongName {}"),
        exploit_code=exploit,
        red_verifier=_ok_red_verifier,
    )
    assert res_missing.category == BluePatchCategory.PATCH_FORMAT_ERROR
    assert res_missing.reward_score == -0.35

    # 3. Whitespace-only no-op -> PATCH_FORMAT_ERROR (-0.35)
    res_noop = verify_patch(
        target_name="TrainAdminTreasury",
        original_source=orig,
        candidate=PatchCandidate(
            target_name="TrainAdminTreasury",
            patched_source="  contract   TrainAdminTreasury {  function f() external {} } ",
        ),
        exploit_code=exploit,
        red_verifier=_ok_red_verifier,
    )
    assert res_noop.category == BluePatchCategory.PATCH_FORMAT_ERROR
    assert res_noop.reward_score == -0.35


def test_red_precondition_fail_closed():
    orig = "contract TrainAdminTreasury { function f() external {} }"
    patched = "contract TrainAdminTreasury { function f() external { require(false); } }"
    with pytest.raises(ValueError, match="Fail-closed Red precondition failed"):
        verify_patch(
            target_name="TrainAdminTreasury",
            original_source=orig,
            candidate=PatchCandidate(target_name="TrainAdminTreasury", patched_source=patched),
            exploit_code="contract ExploitModule {}",
            red_verifier=_fail_red_verifier,
        )


@pytest.mark.parametrize(
    "sb_sequence,expected_cat,expected_reward",
    [
        (
            [PatchSandboxResult(target_name="TrainAdminTreasury", infra_error=True, infra_error_reason="timeout")],
            BluePatchCategory.PATCH_INFRA_ERROR,
            0.0,
        ),
        (
            [PatchSandboxResult(target_name="TrainAdminTreasury", compiled=False, compile_error="SyntaxError")],
            BluePatchCategory.PATCH_COMPILATION_ERROR,
            -0.50,
        ),
        (
            [PatchSandboxResult(target_name="TrainAdminTreasury", compiled=True, functional_pass=False, exploit_blocked=True)],
            BluePatchCategory.FUNCTIONAL_REGRESSION,
            -0.25,
        ),
        (
            [PatchSandboxResult(target_name="TrainAdminTreasury", compiled=True, functional_pass=True, exploit_blocked=False, breach_events=["SecurityInvariantBreached"])],
            BluePatchCategory.EXPLOIT_STILL_SUCCEEDS,
            -0.10,
        ),
        (
            [
                PatchSandboxResult(target_name="TrainAdminTreasury", compiled=True, functional_pass=True, exploit_blocked=True),
                PatchSandboxResult(target_name="TrainAdminTreasury", compiled=True, functional_pass=True, exploit_blocked=False),
            ],
            BluePatchCategory.PATCH_VERIFIED_NO_REPLAY,
            0.50,
        ),
        (
            [
                PatchSandboxResult(target_name="TrainAdminTreasury", compiled=True, functional_pass=True, exploit_blocked=True),
                PatchSandboxResult(target_name="TrainAdminTreasury", compiled=True, functional_pass=True, exploit_blocked=True),
            ],
            BluePatchCategory.PATCH_VERIFIED,
            1.00,
        ),
    ],
)
def test_all_sandbox_outcome_categories(sb_sequence, expected_cat, expected_reward):
    orig = "contract TrainAdminTreasury { address public governance; }"
    patched = "contract TrainAdminTreasury { address public governance; uint256 public v; }"
    calls = iter(sb_sequence)

    res = verify_patch(
        target_name="TrainAdminTreasury",
        original_source=orig,
        candidate=PatchCandidate(target_name="TrainAdminTreasury", patched_source=patched),
        exploit_code="contract ExploitModule {}",
        red_verifier=_ok_red_verifier,
        patch_runner=lambda _n, _s, _e: next(calls),
    )
    assert res.category == expected_cat
    assert res.reward_score == expected_reward
    rec = DualLoopRecord(
        target_name="TrainAdminTreasury",
        red_exploit_code="contract ExploitModule {}",
        red_confirmed=True,
        patch_result=res,
    )
    assert rec.patch_result.category == expected_cat


def test_pilot_functional_test_files_exist():
    assert len(TRAIN_FUNCTIONAL_TESTS) == 5
    for target_name, func_contract in TRAIN_FUNCTIONAL_TESTS.items():
        assert (Path(LOCAL_TRAIN_FUNCTIONAL_TESTS_DIR) / f"{func_contract}.t.sol").is_file()
        assert (SOLIDITY_TRAIN_DIR / f"{target_name}.sol").is_file()


# ---------------------------------------------------------------------------
# Real Foundry integration tests (5 pilot contracts × 4 scenarios)
# ---------------------------------------------------------------------------

PILOT_SCENARIOS: Dict[str, Dict[str, str]] = {
    "TrainAdminTreasury": {
        "exploit": """// SPDX-License-Identifier: MIT
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
""",
        "good_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainAdminTreasury {
    address public governance;
    event GovernanceChanged(address indexed previousGov, address indexed newGov);
    event TreasurySwept(address indexed to, uint256 amount);
    constructor() payable { governance = msg.sender; }
    function updateGovernance(address newGovernance) external {
        require(msg.sender == governance, "not governance");
        require(newGovernance != address(0), "zero address");
        address old = governance;
        governance = newGovernance;
        emit GovernanceChanged(old, newGovernance);
    }
    function sweepTreasury(address payable recipient) external {
        require(msg.sender == governance, "not governance");
        uint256 bal = address(this).balance;
        (bool ok, ) = recipient.call{value: bal}("");
        require(ok, "sweep failed");
        emit TreasurySwept(recipient, bal);
    }
    receive() external payable {}
}
""",
        "bricking_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainAdminTreasury {
    address public governance;
    event GovernanceChanged(address indexed previousGov, address indexed newGov);
    event TreasurySwept(address indexed to, uint256 amount);
    constructor() payable { governance = msg.sender; }
    function updateGovernance(address) external pure { revert("disabled"); }
    function sweepTreasury(address payable) external pure { revert("disabled"); }
    receive() external payable {}
}
""",
        "cosmetic_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainAdminTreasury {
    address public governance;
    event GovernanceChanged(address indexed previousGov, address indexed newGov);
    event TreasurySwept(address indexed to, uint256 amount);
    constructor() payable { governance = msg.sender; }
    function updateGovernance(address newGovernance) external {
        // cosmetic comment only
        require(newGovernance != address(0), "zero address");
        address old = governance;
        governance = newGovernance;
        emit GovernanceChanged(old, newGovernance);
    }
    function sweepTreasury(address payable recipient) external {
        require(msg.sender == governance, "not governance");
        uint256 bal = address(this).balance;
        (bool ok, ) = recipient.call{value: bal}("");
        require(ok, "sweep failed");
        emit TreasurySwept(recipient, bal);
    }
    receive() external payable {}
}
""",
    },
    "TrainShareVault": {
        "exploit": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainShareVault} from "../src/TrainShareVault.sol";
contract ExploitModule {
    TrainShareVault public v;
    constructor(address _v) { v = TrainShareVault(payable(_v)); }
    function runExploit() external payable {
        v.depositAssets{value: 1}();
        (bool ok, ) = address(v).call{value: 3 ether}("");
        require(ok);
    }
    receive() external payable {}
}
""",
        "good_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainShareVault {
    uint256 public totalSupplyShares;
    mapping(address => uint256) public balanceOfShares;
    uint256 private constant VIRTUAL_SHARES = 1e3;
    uint256 private constant VIRTUAL_ASSETS = 1e3;
    event Deposited(address indexed user, uint256 assets, uint256 shares);
    event Redeemed(address indexed user, uint256 assets, uint256 shares);
    function poolAssets() public view returns (uint256) { return address(this).balance; }
    function previewRedeem(uint256 shares) public view returns (uint256) {
        return (shares * (poolAssets() + VIRTUAL_ASSETS)) / (totalSupplyShares + VIRTUAL_SHARES);
    }
    function depositAssets() external payable returns (uint256 shares) {
        require(msg.value > 0, "zero deposit");
        uint256 assetsBefore = address(this).balance - msg.value;
        shares = (msg.value * (totalSupplyShares + VIRTUAL_SHARES)) / (assetsBefore + VIRTUAL_ASSETS);
        require(shares > 0, "zero shares");
        totalSupplyShares += shares;
        balanceOfShares[msg.sender] += shares;
        emit Deposited(msg.sender, msg.value, shares);
    }
    function redeemShares(uint256 shares) external returns (uint256 assets) {
        require(shares > 0 && balanceOfShares[msg.sender] >= shares, "bad shares");
        assets = previewRedeem(shares);
        require(assets > 0, "zero payout");
        balanceOfShares[msg.sender] -= shares;
        totalSupplyShares -= shares;
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok, "eth transfer failed");
        emit Redeemed(msg.sender, assets, shares);
    }
    receive() external payable {}
}
""",
        "bricking_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainShareVault {
    uint256 public totalSupplyShares;
    mapping(address => uint256) public balanceOfShares;
    function poolAssets() public view returns (uint256) { return address(this).balance; }
    function previewRedeem(uint256) public pure returns (uint256) { return 0; }
    function depositAssets() external payable returns (uint256) { revert("disabled"); }
    function redeemShares(uint256) external pure returns (uint256) { revert("disabled"); }
    receive() external payable {}
}
""",
        "cosmetic_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainShareVault {
    uint256 public totalSupplyShares;
    mapping(address => uint256) public balanceOfShares;
    event Deposited(address indexed user, uint256 assets, uint256 shares);
    event Redeemed(address indexed user, uint256 assets, uint256 shares);
    function poolAssets() public view returns (uint256) { return address(this).balance; }
    function previewRedeem(uint256 shares) public view returns (uint256) {
        if (totalSupplyShares == 0) return shares;
        return (shares * poolAssets()) / totalSupplyShares;
    }
    function depositAssets() external payable returns (uint256 shares) {
        // cosmetic comment
        require(msg.value > 0, "zero deposit");
        uint256 assetsBefore = address(this).balance - msg.value;
        if (totalSupplyShares == 0 || assetsBefore == 0) { shares = msg.value; }
        else { shares = (msg.value * totalSupplyShares) / assetsBefore; }
        totalSupplyShares += shares;
        balanceOfShares[msg.sender] += shares;
        emit Deposited(msg.sender, msg.value, shares);
    }
    function redeemShares(uint256 shares) external returns (uint256 assets) {
        require(shares > 0 && balanceOfShares[msg.sender] >= shares, "bad shares");
        assets = (shares * poolAssets()) / totalSupplyShares;
        require(assets > 0, "zero payout");
        balanceOfShares[msg.sender] -= shares;
        totalSupplyShares -= shares;
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok, "eth transfer failed");
        emit Redeemed(msg.sender, assets, shares);
    }
    receive() external payable {}
}
""",
    },
    "TrainReentrancyBank": {
        "exploit": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainReentrancyBank} from "../src/TrainReentrancyBank.sol";
contract ExploitModule {
    TrainReentrancyBank public b;
    uint256 public count;
    constructor(address _b) { b = TrainReentrancyBank(payable(_b)); }
    function runExploit() external payable {
        b.depositFunds{value: msg.value}();
        b.cashOut();
    }
    receive() external payable {
        if (count < 5 && address(b).balance >= 1 ether) {
            count++;
            b.cashOut();
        }
    }
}
""",
        "good_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainReentrancyBank {
    mapping(address => uint256) public ledger;
    event Deposited(address indexed account, uint256 amount);
    event CashedOut(address indexed account, uint256 amount);
    function depositFunds() external payable {
        require(msg.value > 0, "zero");
        ledger[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
    function cashOut() external {
        uint256 amount = ledger[msg.sender];
        require(amount > 0, "empty");
        ledger[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit CashedOut(msg.sender, amount);
    }
}
""",
        "bricking_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainReentrancyBank {
    mapping(address => uint256) public ledger;
    function depositFunds() external payable { revert("disabled"); }
    function cashOut() external pure { revert("disabled"); }
}
""",
        "cosmetic_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainReentrancyBank {
    mapping(address => uint256) public ledger;
    event Deposited(address indexed account, uint256 amount);
    event CashedOut(address indexed account, uint256 amount);
    function depositFunds() external payable {
        require(msg.value > 0, "zero");
        ledger[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
    function cashOut() external {
        // cosmetic comment
        uint256 amount = ledger[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        ledger[msg.sender] = 0;
        emit CashedOut(msg.sender, amount);
    }
}
""",
    },
    "TrainUninitializedVault": {
        "exploit": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainUninitializedVault} from "../src/TrainUninitializedVault.sol";
contract ExploitModule {
    TrainUninitializedVault public v;
    constructor(address _v) { v = TrainUninitializedVault(payable(_v)); }
    function runExploit() external {
        v.initialize(address(this));
        v.drain(payable(address(this)));
    }
    receive() external payable {}
}
""",
        "good_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainUninitializedVault {
    address public admin;
    bool public initialized;
    event Initialized(address indexed admin);
    event Drained(address indexed to, uint256 amount);
    constructor() payable {
        admin = msg.sender;
        initialized = true;
        emit Initialized(msg.sender);
    }
    function initialize(address _admin) external {
        require(!initialized, "already initialized");
        require(_admin != address(0), "zero admin");
        admin = _admin;
        initialized = true;
        emit Initialized(_admin);
    }
    function drain(address payable to) external {
        require(initialized && msg.sender == admin, "not admin");
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "drain failed");
        emit Drained(to, bal);
    }
    receive() external payable {}
}
""",
        "bricking_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainUninitializedVault {
    address public admin;
    bool public initialized;
    constructor() payable { revert("disabled"); }
    function initialize(address) external pure { revert("disabled"); }
    function drain(address payable) external pure { revert("disabled"); }
    receive() external payable {}
}
""",
        "cosmetic_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainUninitializedVault {
    address public admin;
    bool public initialized;
    event Initialized(address indexed admin);
    event Drained(address indexed to, uint256 amount);
    constructor() payable {}
    function initialize(address _admin) external {
        // cosmetic comment
        require(!initialized, "already initialized");
        require(_admin != address(0), "zero admin");
        admin = _admin;
        initialized = true;
        emit Initialized(_admin);
    }
    function drain(address payable to) external {
        require(initialized && msg.sender == admin, "not admin");
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "drain failed");
        emit Drained(to, bal);
    }
    receive() external payable {}
}
""",
    },
    "TrainTimelockBypass": {
        "exploit": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {TrainTimelockBypass} from "../src/TrainTimelockBypass.sol";
contract ExploitModule {
    TrainTimelockBypass public tl;
    constructor(address _tl) { tl = TrainTimelockBypass(payable(_tl)); }
    function runExploit() external {
        tl.execute(payable(address(this)), 1 ether, "");
    }
    receive() external payable {}
}
""",
        "good_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainTimelockBypass {
    address public admin;
    uint256 public constant DELAY = 2 days;
    mapping(bytes32 => uint256) public eta;
    constructor() payable { admin = msg.sender; }
    function queue(address payable to, uint256 amount, bytes calldata data) external returns (bytes32 txId) {
        require(msg.sender == admin, "not admin");
        txId = keccak256(abi.encode(to, amount, data));
        eta[txId] = block.timestamp + DELAY;
    }
    function execute(address payable to, uint256 amount, bytes calldata data) external {
        bytes32 txId = keccak256(abi.encode(to, amount, data));
        require(eta[txId] != 0, "not queued");
        require(block.timestamp >= eta[txId], "timelock not ready");
        require(address(this).balance >= amount, "empty");
        eta[txId] = 0;
        (bool ok, ) = to.call{value: amount}(data);
        require(ok, "exec failed");
    }
    receive() external payable {}
}
""",
        "bricking_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainTimelockBypass {
    address public admin;
    uint256 public constant DELAY = 2 days;
    mapping(bytes32 => uint256) public eta;
    constructor() payable { admin = msg.sender; }
    function queue(address payable, uint256, bytes calldata) external pure returns (bytes32) { revert("disabled"); }
    function execute(address payable, uint256, bytes calldata) external pure { revert("disabled"); }
    receive() external payable {}
}
""",
        "cosmetic_patch": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TrainTimelockBypass {
    address public admin;
    uint256 public constant DELAY = 2 days;
    mapping(bytes32 => uint256) public eta;
    constructor() payable { admin = msg.sender; }
    function queue(address payable to, uint256 amount, bytes calldata data) external returns (bytes32 txId) {
        require(msg.sender == admin, "not admin");
        txId = keccak256(abi.encode(to, amount, data));
        eta[txId] = block.timestamp + DELAY;
    }
    function execute(address payable to, uint256 amount, bytes calldata data) external {
        // cosmetic comment
        bytes32 txId = keccak256(abi.encode(to, amount, data));
        require(block.timestamp >= eta[txId], "timelock not ready");
        require(address(this).balance >= amount, "empty");
        eta[txId] = 0;
        (bool ok, ) = to.call{value: amount}(data);
        require(ok, "exec failed");
    }
    receive() external payable {}
}
""",
    },
}


@pytest.mark.parametrize("target_name", list(PILOT_SCENARIOS.keys()))
def test_real_foundry_dual_loop_4_scenarios(target_name: str):
    if not is_patch_sandbox_available():
        import os
        if os.environ.get("FOUNDRY_CI", "").lower() == "true":
            pytest.fail("FOUNDRY_CI=true requires `forge` and `forge-std` to be available")
        pytest.skip("Foundry `forge` + `forge-std` not available locally")

    spec = PILOT_SCENARIOS[target_name]
    original_source = (SOLIDITY_TRAIN_DIR / f"{target_name}.sol").read_text(encoding="utf-8")
    exploit_code = spec["exploit"]

    # 1. Original contract + Red ExploitModule -> EXPLOIT_CONFIRMED
    red_target = TargetProgram(name=target_name, source_code=original_source, language="solidity")
    red_payload = ExploitPayload(
        target_name=target_name,
        hypothesis=AttackHypothesis(
            vulnerability_type="red_precondition",
            reasoning_trace="Verify Red exploit breaches original contract",
            attack_vector="red_exploit",
        ),
        test_code=exploit_code,
        format_valid=True,
        raw_model_response=exploit_code,
    )
    red_res = run_payload_in_sandbox(red_target, red_payload, allow_train_split=True)
    assert red_res.category == ResultCategory.EXPLOIT_CONFIRMED, red_res.stderr

    # 2. Good minimal patch -> PATCH_VERIFIED (+1.0)
    good_res = verify_patch(
        target_name=target_name,
        original_source=original_source,
        candidate=PatchCandidate(target_name=target_name, patched_source=spec["good_patch"]),
        exploit_code=exploit_code,
        red_precondition_verified=True,
    )
    assert good_res.category == BluePatchCategory.PATCH_VERIFIED
    assert good_res.reward_score == 1.0
    assert good_res.functional_pass is True
    assert good_res.exploit_blocked is True
    assert good_res.reproducibility_confirmed is True

    # 3. Trivial bricking patch -> FUNCTIONAL_REGRESSION (-0.25)
    brick_res = verify_patch(
        target_name=target_name,
        original_source=original_source,
        candidate=PatchCandidate(target_name=target_name, patched_source=spec["bricking_patch"]),
        exploit_code=exploit_code,
        red_precondition_verified=True,
    )
    assert brick_res.category == BluePatchCategory.FUNCTIONAL_REGRESSION
    assert brick_res.reward_score == -0.25

    # 4. Cosmetic ineffective patch -> EXPLOIT_STILL_SUCCEEDS (-0.10)
    cosm_res = verify_patch(
        target_name=target_name,
        original_source=original_source,
        candidate=PatchCandidate(target_name=target_name, patched_source=spec["cosmetic_patch"]),
        exploit_code=exploit_code,
        red_precondition_verified=True,
    )
    assert cosm_res.category == BluePatchCategory.EXPLOIT_STILL_SUCCEEDS
    assert cosm_res.reward_score == -0.10
