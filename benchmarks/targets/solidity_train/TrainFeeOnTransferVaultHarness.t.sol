// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {MockFeeToken, TrainFeeOnTransferVault} from "../src/TrainFeeOnTransferVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainFeeOnTransferVaultHarness is Test {
    MockFeeToken public token;
    TrainFeeOnTransferVault public vault;
    uint256 public constant INITIAL_VAULT_TOKENS = 1_000 ether;
    uint256 public constant ATTACKER_TOKENS = 100 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        token = new MockFeeToken();
        vault = new TrainFeeOnTransferVault(address(token));
        token.mint(address(vault), INITIAL_VAULT_TOKENS);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        token.mint(address(exploit), ATTACKER_TOKENS);
        exploit.runExploit();

        uint256 vaultBal = token.balanceOf(address(vault));
        if (vaultBal < INITIAL_VAULT_TOKENS) {
            emit SecurityInvariantBreached("FEE_ON_TRANSFER_ACCOUNTING_DRAIN", INITIAL_VAULT_TOKENS - vaultBal);
            return;
        }
        revert("EXPLOIT_FAILED: Vault token reserve remained intact");
    }
}
