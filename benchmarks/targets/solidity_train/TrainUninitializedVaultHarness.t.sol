// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainUninitializedVault} from "../src/TrainUninitializedVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainUninitializedVaultHarness is Test {
    TrainUninitializedVault public vault;
    uint256 public constant INITIAL_VAULT = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainUninitializedVault{value: INITIAL_VAULT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        exploit.runExploit();

        if (address(vault).balance < INITIAL_VAULT || vault.initialized()) {
            uint256 deficit = address(vault).balance < INITIAL_VAULT
                ? INITIAL_VAULT - address(vault).balance
                : 1;
            emit SecurityInvariantBreached("UNINITIALIZED_ADMIN_TAKEOVER", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Uninitialized vault remained untouched");
    }

    receive() external payable {}
}
