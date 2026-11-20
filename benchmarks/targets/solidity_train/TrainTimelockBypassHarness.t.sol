// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainTimelockBypass} from "../src/TrainTimelockBypass.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainTimelockBypassHarness is Test {
    TrainTimelockBypass public timelock;
    uint256 public constant INITIAL_TREASURY = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        timelock = new TrainTimelockBypass{value: INITIAL_TREASURY}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(timelock));
        exploit.runExploit();

        if (address(timelock).balance < INITIAL_TREASURY) {
            emit SecurityInvariantBreached("TIMELOCK_ZERO_ETA_BYPASS", INITIAL_TREASURY - address(timelock).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Timelock prevented unqueued execution");
    }

    receive() external payable {}
}
