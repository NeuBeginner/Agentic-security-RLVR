// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainMsgValueBatch} from "../src/TrainMsgValueBatch.sol";

contract TrainMsgValueBatchFunctional is Test {
    TrainMsgValueBatch public vault;
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);
    address public carol = address(0xCA201);

    function setUp() public {
        vault = new TrainMsgValueBatch();
        vm.deal(alice, 5 ether);
        vm.deal(carol, 5 ether);
    }

    function testSingleAndBatchDepositWithdrawAccounting() public {
        vm.prank(alice);
        vault.depositSingle{value: 2 ether}();
        assertEq(vault.deposits(alice), 2 ether, "single deposit mismatch");

        address[] memory recipients = new address[](2);
        recipients[0] = bob;
        recipients[1] = carol;

        vm.prank(carol);
        vault.batchDeposit{value: 2 ether}(recipients);

        assertEq(vault.deposits(bob), 1 ether, "bob batch credit mismatch");
        assertEq(vault.deposits(carol), 1 ether, "carol batch credit mismatch");
        assertEq(address(vault).balance, 4 ether, "vault eth balance mismatch");

        uint256 bobBefore = bob.balance;
        vm.prank(bob);
        vault.withdraw();
        assertEq(bob.balance, bobBefore + 1 ether, "bob withdraw mismatch");
        assertEq(vault.deposits(bob), 0, "bob deposit not cleared");
    }
}
