// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainCallbackPool} from "../src/TrainCallbackPool.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainCallbackPoolHarness is Test {
    TrainCallbackPool public pool;
    uint256 public constant INITIAL_RESERVE = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        pool = new TrainCallbackPool{value: INITIAL_RESERVE}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        exploit.runExploit();

        if (address(pool).balance < INITIAL_RESERVE) {
            emit SecurityInvariantBreached("ARBITRARY_EXTERNAL_CALL_DRAIN", INITIAL_RESERVE - address(pool).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Pool reserve remained protected");
    }

    receive() external payable {}
}
