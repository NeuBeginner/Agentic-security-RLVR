// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainZeroSigVault} from "../src/TrainZeroSigVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainZeroSigVaultHarness is Test {
    TrainZeroSigVault public vault;
    address public signer = address(0x5169);
    uint256 public constant INITIAL_VAULT = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainZeroSigVault{value: INITIAL_VAULT}(signer);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        exploit.runExploit();

        if (address(vault).balance < INITIAL_VAULT) {
            emit SecurityInvariantBreached("ZERO_ADDRESS_ECRECOVER_BYPASS", INITIAL_VAULT - address(vault).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Invalid signature rejected");
    }

    receive() external payable {}
}
