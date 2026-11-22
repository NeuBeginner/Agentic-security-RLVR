// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainReentrancyBank} from "../src/TrainReentrancyBank.sol";

contract TrainReentrancyBankFunctional is Test {
    TrainReentrancyBank public bank;
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);

    function setUp() public {
        bank = new TrainReentrancyBank();
        vm.deal(alice, 5 ether);
        vm.deal(bob, 5 ether);
    }

    function testLegitimateDepositAndCashOut() public {
        vm.prank(alice);
        bank.depositFunds{value: 3 ether}();

        vm.prank(bob);
        bank.depositFunds{value: 2 ether}();

        vm.prank(alice);
        bank.cashOut();
        assertEq(alice.balance, 5 ether, "alice balance mismatch after cashOut");
        assertEq(bank.ledger(alice), 0, "alice ledger not cleared");

        vm.prank(bob);
        bank.cashOut();
        assertEq(bob.balance, 5 ether, "bob balance mismatch after cashOut");
        assertEq(bank.ledger(bob), 0, "bob ledger not cleared");
    }
}
