// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainRewardPool} from "../src/TrainRewardPool.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainRewardPoolHarness is Test {
    TrainRewardPool public pool;
    uint256 public constant INITIAL_RESERVE = 8 ether;
    uint256 public constant ATTACKER_BUDGET = 2 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        pool = new TrainRewardPool{value: INITIAL_RESERVE}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        // Max fair single-block reward is 10% of attacker budget = 0.2 ether
        uint256 maxFairPayout = (ATTACKER_BUDGET * 1000) / 10000;
        if (address(pool).balance < INITIAL_RESERVE - maxFairPayout) {
            uint256 deficit = (INITIAL_RESERVE - maxFairPayout) - address(pool).balance;
            emit SecurityInvariantBreached("REWARD_ACCOUNTING_DRAIN", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Reward pool reserve preserved");
    }

    receive() external payable {}
}
