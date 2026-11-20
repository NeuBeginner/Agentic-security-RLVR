// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {MockChainlinkFeed, TrainStaleOracleFeed} from "../src/TrainStaleOracleFeed.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainStaleOracleFeedHarness is Test {
    MockChainlinkFeed public feed;
    TrainStaleOracleFeed public pool;
    uint256 public constant INITIAL_POOL = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        feed = new MockChainlinkFeed();
        feed.setPrice(int256(10 ether), block.timestamp);
        vm.warp(block.timestamp + 7 days);
        pool = new TrainStaleOracleFeed{value: INITIAL_POOL}(address(feed));
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(pool).balance < INITIAL_POOL) {
            emit SecurityInvariantBreached("ORACLE_STALE_OR_ZERO_PRICE_DRAIN", INITIAL_POOL - address(pool).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Stale oracle borrow rejected");
    }

    receive() external payable {}
}
