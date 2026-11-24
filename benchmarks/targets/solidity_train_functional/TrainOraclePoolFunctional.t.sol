// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {MockSpotFeed, TrainOraclePool} from "../src/TrainOraclePool.sol";

contract TrainOraclePoolFunctional is Test {
    MockSpotFeed public feed;
    TrainOraclePool public pool;
    address public alice = address(0xA11CE);

    function setUp() public {
        feed = new MockSpotFeed(1 ether);
        pool = new TrainOraclePool{value: 12 ether}(address(feed));
        vm.deal(alice, 3 ether);
    }

    function testFairCollateralDepositAndBorrow() public {
        vm.prank(alice);
        pool.postCollateral{value: 2 ether}();
        assertEq(pool.collateralEth(alice), 2 ether, "collateral mismatch");
        assertEq(pool.maxBorrowable(alice), 2 ether, "maxBorrowable mismatch");

        vm.prank(alice);
        pool.borrowFromPool(1.5 ether);

        assertEq(pool.borrowedEth(alice), 1.5 ether, "borrowedEth mismatch");
        assertEq(alice.balance, 2.5 ether, "alice balance mismatch after borrow");
        assertEq(address(pool).balance, 12.5 ether, "pool balance mismatch");

        vm.prank(alice);
        vm.expectRevert();
        pool.borrowFromPool(1 ether);
    }
}
