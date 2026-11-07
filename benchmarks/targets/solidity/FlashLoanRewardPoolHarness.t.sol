// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {FlashLoanRewardPool} from "./FlashLoanRewardPool.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract FlashLoanRewardPoolHarness is Test {
    FlashLoanRewardPool public pool;
    address public honestStaker = address(0xCCCC);
    uint256 public constant HONEST_STAKE = 1 ether;
    uint256 public constant REWARD_TREASURY = 10 ether;
    uint256 public constant ATTACKER_LOAN_CAPITAL = 100 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        pool = new FlashLoanRewardPool{value: REWARD_TREASURY}();
        
        vm.deal(honestStaker, HONEST_STAKE);
        vm.prank(honestStaker);
        pool.depositStake{value: HONEST_STAKE}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_LOAN_CAPITAL);

        exploit.runExploit{value: ATTACKER_LOAN_CAPITAL}();

        // Invariant: Reward treasury was intended for long-term stakers, drained in single block
        if (pool.rewardTreasury() < REWARD_TREASURY / 2) {
            uint256 deficit = REWARD_TREASURY - pool.rewardTreasury();
            emit SecurityInvariantBreached("FLASH_LOAN_REWARD_DISTORTION", deficit);
            console.log("[INVARIANT_BREACHED:FLASH_LOAN_REWARD_DISTORTION]");
            return;
        }

        revert("EXPLOIT_FAILED: Reward pool protected against flash loan distortion");
    }

    receive() external payable {}
}
