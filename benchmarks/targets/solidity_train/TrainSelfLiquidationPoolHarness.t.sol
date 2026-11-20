// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainSelfLiquidationPool} from "../src/TrainSelfLiquidationPool.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainSelfLiquidationPoolHarness is Test {
    TrainSelfLiquidationPool public pool;
    uint256 public constant INITIAL_POOL_RESERVE = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        pool = new TrainSelfLiquidationPool{value: INITIAL_POOL_RESERVE}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(pool).balance < INITIAL_POOL_RESERVE) {
            emit SecurityInvariantBreached("SELF_LIQUIDATION_BONUS_DRAIN", INITIAL_POOL_RESERVE - address(pool).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Lending pool reserve remained intact");
    }

    receive() external payable {}
}
