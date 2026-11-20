// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {MockBoolToken, TrainUncheckedTransferPool} from "../src/TrainUncheckedTransferPool.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainUncheckedTransferPoolHarness is Test {
    MockBoolToken public token;
    TrainUncheckedTransferPool public pool;
    uint256 public constant INITIAL_POOL_TOKENS = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        token = new MockBoolToken();
        pool = new TrainUncheckedTransferPool(address(token));
        token.mint(address(pool), INITIAL_POOL_TOKENS);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        exploit.runExploit();

        uint256 poolBal = token.balanceOf(address(pool));
        if (poolBal < INITIAL_POOL_TOKENS) {
            emit SecurityInvariantBreached("UNCHECKED_TRANSFER_RETURN_DRAIN", INITIAL_POOL_TOKENS - poolBal);
            return;
        }
        revert("EXPLOIT_FAILED: Pool token balance remained intact");
    }
}
