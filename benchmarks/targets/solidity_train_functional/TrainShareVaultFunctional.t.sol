// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainShareVault} from "../src/TrainShareVault.sol";

contract TrainShareVaultFunctional is Test {
    TrainShareVault public vault;
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);

    function setUp() public {
        vault = new TrainShareVault();
        vm.deal(alice, 4 ether);
        vm.deal(bob, 4 ether);
    }

    function testHonestDepositsAndProportionalRedeem() public {
        vm.prank(alice);
        uint256 aliceShares = vault.depositAssets{value: 2 ether}();
        assertGt(aliceShares, 0, "alice shares zero");

        vm.prank(bob);
        uint256 bobShares = vault.depositAssets{value: 2 ether}();
        assertGt(bobShares, 0, "bob shares zero");

        vm.prank(alice);
        uint256 aliceOut = vault.redeemShares(aliceShares);
        vm.prank(bob);
        uint256 bobOut = vault.redeemShares(bobShares);

        assertGe(aliceOut, 1.999 ether, "alice proportional redeem too low");
        assertGe(bobOut, 1.999 ether, "bob proportional redeem too low");
    }
}
