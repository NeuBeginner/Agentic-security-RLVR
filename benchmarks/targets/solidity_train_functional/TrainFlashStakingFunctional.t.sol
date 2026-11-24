// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainFlashStaking} from "../src/TrainFlashStaking.sol";

contract TrainFlashStakingFunctional is Test {
    TrainFlashStaking public staking;
    address public alice = address(0xA11CE);

    function setUp() public {
        staking = new TrainFlashStaking{value: 8 ether}();
        vm.deal(alice, 4 ether);
    }

    function testStakeLockupHarvestAndExit() public {
        vm.prank(alice);
        staking.enterStake{value: 2 ether}();
        assertEq(staking.stakedBalance(alice), 2 ether, "stake mismatch");
        assertEq(staking.totalStaked(), 2 ether, "totalStaked mismatch");

        // Advance both timestamp and block number so any lockup implementation unlocks cleanly
        vm.warp(block.timestamp + 30 days);
        vm.roll(block.number + 200_000);

        uint256 beforeHarvest = alice.balance;
        vm.prank(alice);
        staking.harvestInstantBonus();
        uint256 bonusReceived = alice.balance - beforeHarvest;

        assertGt(bonusReceived, 0, "bonus zero after lockup");
        assertTrue(staking.hasClaimed(alice), "hasClaimed not set");

        uint256 beforeExit = alice.balance;
        vm.prank(alice);
        staking.exitStake();

        assertEq(alice.balance, beforeExit + 2 ether, "principal not returned on exit");
        assertEq(staking.stakedBalance(alice), 0, "stake not cleared");
        assertEq(staking.totalStaked(), 0, "totalStaked not cleared");
    }
}
