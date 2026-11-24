// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainRoundingZeroVault} from "../src/TrainRoundingZeroVault.sol";

contract TrainRoundingZeroVaultFunctional is Test {
    TrainRoundingZeroVault public vault;
    address public saver = address(0x5A7E);
    address public alice = address(0xA11CE);

    function setUp() public {
        vault = new TrainRoundingZeroVault();
        vault.seedInitial{value: 10 ether}(saver, 1_000);
        vm.deal(alice, 5 ether);
    }

    function testProportionalDepositAndWithdraw() public {
        vm.prank(alice);
        vault.deposit{value: 5 ether}();

        assertEq(vault.shares(alice), 500, "alice shares mismatch");
        assertEq(vault.totalSupply(), 1_500, "totalSupply mismatch");
        assertEq(vault.totalAssets(), 15 ether, "totalAssets mismatch");

        vm.prank(alice);
        vault.withdrawAssets(5 ether);

        assertEq(alice.balance, 5 ether, "alice balance mismatch after withdraw");
        assertEq(vault.shares(alice), 0, "alice shares not burned");
        assertEq(vault.totalSupply(), 1_000, "final totalSupply mismatch");
        assertEq(vault.totalAssets(), 10 ether, "final totalAssets mismatch");
    }
}
