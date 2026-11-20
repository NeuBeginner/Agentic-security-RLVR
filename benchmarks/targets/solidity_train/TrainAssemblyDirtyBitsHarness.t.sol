// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainAssemblyDirtyBits} from "../src/TrainAssemblyDirtyBits.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainAssemblyDirtyBitsHarness is Test {
    TrainAssemblyDirtyBits public faucet;
    uint256 public constant INITIAL_FAUCET = 10 ether;
    uint256 public constant MAX_SINGLE_CLAIM = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        faucet = new TrainAssemblyDirtyBits{value: INITIAL_FAUCET}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(faucet));
        exploit.runExploit();

        if (address(faucet).balance < INITIAL_FAUCET - MAX_SINGLE_CLAIM) {
            emit SecurityInvariantBreached(
                "INLINE_ASSEMBLY_DIRTY_BITS_BYPASS",
                (INITIAL_FAUCET - MAX_SINGLE_CLAIM) - address(faucet).balance
            );
            return;
        }
        revert("EXPLOIT_FAILED: Single-claim limit enforced");
    }

    receive() external payable {}
}
