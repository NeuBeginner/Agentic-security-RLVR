// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {MockFeeToken, TrainFeeOnTransferVault} from "../src/TrainFeeOnTransferVault.sol";

contract TrainFeeOnTransferVaultFunctional is Test {
    MockFeeToken public token;
    TrainFeeOnTransferVault public vault;
    address public alice = address(0xA11CE);

    function setUp() public {
        token = new MockFeeToken();
        vault = new TrainFeeOnTransferVault(address(token));
        token.mint(alice, 100 ether);
    }

    function testActualReceivedDepositAndWithdraw() public {
        vm.startPrank(alice);
        token.approve(address(vault), 100 ether);
        vault.deposit(100 ether);

        // MockFeeToken takes 10% fee -> vault receives 90 ether
        assertEq(token.balanceOf(address(vault)), 90 ether, "vault token balance mismatch");
        assertEq(vault.balances(alice), 90 ether, "alice credited pre-fee instead of net");

        vm.expectRevert();
        vault.withdraw(91 ether);

        vault.withdraw(90 ether);
        vm.stopPrank();

        assertEq(vault.balances(alice), 0, "alice balance not cleared");
        assertEq(token.balanceOf(address(vault)), 0, "vault not emptied");
        assertEq(token.balanceOf(alice), 81 ether, "alice net withdrawal mismatch");
    }
}
