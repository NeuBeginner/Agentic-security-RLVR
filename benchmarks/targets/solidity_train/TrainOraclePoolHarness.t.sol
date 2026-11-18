// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainOraclePool, MockSpotFeed} from "../src/TrainOraclePool.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainOraclePoolHarness is Test {
    MockSpotFeed public feed;
    TrainOraclePool public pool;
    uint256 public constant POOL_LIQUIDITY = 12 ether;
    uint256 public constant ATTACKER_COLLATERAL = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        feed = new MockSpotFeed(1 ether); // 1:1 initial price
        pool = new TrainOraclePool{value: POOL_LIQUIDITY}(address(feed));
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_COLLATERAL);
        exploit.runExploit{value: ATTACKER_COLLATERAL}();

        if (address(pool).balance < POOL_LIQUIDITY - ATTACKER_COLLATERAL) {
            uint256 deficit = (POOL_LIQUIDITY - ATTACKER_COLLATERAL) - address(pool).balance;
            emit SecurityInvariantBreached("ORACLE_PRICE_MANIPULATION", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Borrow remained bounded by fair collateral");
    }

    receive() external payable {}
}
