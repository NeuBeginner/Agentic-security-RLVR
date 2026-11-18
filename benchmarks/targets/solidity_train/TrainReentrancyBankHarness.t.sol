// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainReentrancyBank} from "../src/TrainReentrancyBank.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainReentrancyBankHarness is Test {
    TrainReentrancyBank public bank;
    address public saver = address(0x5A7E);
    uint256 public constant SAVER_DEPOSIT = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        bank = new TrainReentrancyBank();
        vm.deal(saver, SAVER_DEPOSIT);
        vm.prank(saver);
        bank.depositFunds{value: SAVER_DEPOSIT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(bank));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(bank).balance < bank.ledger(saver)) {
            uint256 deficit = bank.ledger(saver) - address(bank).balance;
            emit SecurityInvariantBreached("DEPOSITOR_SOLVENCY_COLLAPSE", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Bank remained solvent");
    }

    receive() external payable {}
}
