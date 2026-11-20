// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainCrossFuncVault} from "../src/TrainCrossFuncVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainCrossFuncVaultHarness is Test {
    TrainCrossFuncVault public vault;
    address public saver = address(0x5A7E);
    uint256 public constant SAVER_DEPOSIT = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainCrossFuncVault();
        vm.deal(saver, SAVER_DEPOSIT);
        vm.prank(saver);
        vault.deposit{value: SAVER_DEPOSIT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(vault).balance < vault.balances(saver)) {
            uint256 deficit = vault.balances(saver) - address(vault).balance;
            emit SecurityInvariantBreached("CROSS_FUNCTION_REENTRANCY_DRAIN", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Vault remained solvent");
    }

    receive() external payable {}
}
