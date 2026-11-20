// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainRoundingZeroVault} from "../src/TrainRoundingZeroVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainRoundingZeroVaultHarness is Test {
    TrainRoundingZeroVault public vault;
    address public saver = address(0x5A7E);
    uint256 public constant INITIAL_ASSETS = 10 ether;
    uint256 public constant INITIAL_SHARES = 1_000;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainRoundingZeroVault();
        vault.seedInitial{value: INITIAL_ASSETS}(saver, INITIAL_SHARES);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        exploit.runExploit();

        if (address(vault).balance < INITIAL_ASSETS) {
            emit SecurityInvariantBreached("ZERO_SHARES_ROUNDING_DRAIN", INITIAL_ASSETS - address(vault).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Vault assets remained intact");
    }

    receive() external payable {}
}
