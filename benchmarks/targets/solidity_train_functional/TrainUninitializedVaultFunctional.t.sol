// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainUninitializedVault} from "../src/TrainUninitializedVault.sol";

contract TrainUninitializedVaultFunctional is Test {
    TrainUninitializedVault public vault;

    function setUp() public {
        vault = new TrainUninitializedVault{value: 4 ether}();
    }

    function testSingleInitializationAndAdminDrain() public {
        address payable recipient = payable(address(0x5678));

        if (!vault.initialized()) {
            vault.initialize(address(this));
        }
        assertTrue(vault.initialized(), "vault not initialized");
        assertEq(vault.admin(), address(this), "admin mismatch");

        vault.drain(recipient);
        assertEq(recipient.balance, 4 ether, "recipient did not receive funds");
        assertEq(address(vault).balance, 0, "vault not drained");
    }
}
