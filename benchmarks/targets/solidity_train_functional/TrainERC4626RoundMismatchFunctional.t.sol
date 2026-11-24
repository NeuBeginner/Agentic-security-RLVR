// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainERC4626RoundMismatch} from "../src/TrainERC4626RoundMismatch.sol";

contract TrainERC4626RoundMismatchFunctional is Test {
    TrainERC4626RoundMismatch public vault;
    address public saver = address(0x5A7E);
    address public alice = address(0xA11CE);

    function setUp() public {
        vault = new TrainERC4626RoundMismatch();
        vault.seed{value: 10 ether}(saver, 1_000);
        vm.deal(alice, 5 ether);
    }

    function testExactProportionalDepositAndRedeem() public {
        vm.prank(alice);
        uint256 minted = vault.deposit{value: 5 ether}();

        assertEq(minted, 500, "minted shares mismatch");
        assertEq(vault.shares(alice), 500, "alice shares mismatch");
        assertEq(vault.totalSupply(), 1_500, "totalSupply mismatch");
        assertEq(vault.totalAssets(), 15 ether, "totalAssets mismatch");

        vm.prank(alice);
        uint256 assetsOut = vault.redeem(500);

        assertEq(assetsOut, 5 ether, "redeemed assets mismatch");
        assertEq(alice.balance, 5 ether, "alice eth balance mismatch");
        assertEq(vault.shares(alice), 0, "alice shares not cleared");
        assertEq(vault.totalSupply(), 1_000, "final totalSupply mismatch");
        assertEq(vault.totalAssets(), 10 ether, "final totalAssets mismatch");
    }
}
