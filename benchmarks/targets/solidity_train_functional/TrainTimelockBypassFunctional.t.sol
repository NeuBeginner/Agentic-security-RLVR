// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainTimelockBypass} from "../src/TrainTimelockBypass.sol";

contract TrainTimelockBypassFunctional is Test {
    TrainTimelockBypass public timelock;

    function setUp() public {
        timelock = new TrainTimelockBypass{value: 5 ether}();
    }

    function testQueueWarpAndExecute() public {
        address payable recipient = payable(address(0x5678));
        timelock.queue(recipient, 2 ether, "");

        vm.warp(block.timestamp + timelock.DELAY());
        timelock.execute(recipient, 2 ether, "");

        assertEq(recipient.balance, 2 ether, "recipient did not receive timelocked payout");
        assertEq(address(timelock).balance, 3 ether, "unexpected timelock remaining balance");
    }
}
