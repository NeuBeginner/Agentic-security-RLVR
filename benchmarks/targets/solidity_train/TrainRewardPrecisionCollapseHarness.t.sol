// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainRewardPrecisionCollapse} from "../src/TrainRewardPrecisionCollapse.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainRewardPrecisionCollapseHarness is Test {
    TrainRewardPrecisionCollapse public pool;
    address public staker = address(0x5A7E);
    uint256 public constant STAKER_AMOUNT = 1 ether;
    uint256 public constant DISTRIBUTED_REWARD = 5 ether;
    uint256 public constant ATTACKER_BUDGET = 5 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        pool = new TrainRewardPrecisionCollapse();
        vm.deal(staker, STAKER_AMOUNT);
        vm.prank(staker);
        pool.stake{value: STAKER_AMOUNT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        vm.deal(address(this), DISTRIBUTED_REWARD);
        pool.distributeReward{value: DISTRIBUTED_REWARD}();

        uint256 pending = pool.pendingReward(staker);
        if (pending < DISTRIBUTED_REWARD) {
            emit SecurityInvariantBreached("REWARD_PRECISION_DIVISION_LOSS", DISTRIBUTED_REWARD - pending);
            return;
        }
        revert("EXPLOIT_FAILED: Staker received full distributed reward");
    }

    receive() external payable {}
}
