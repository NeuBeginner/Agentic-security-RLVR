// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainReadOnlyReentrancy} from "../src/TrainReadOnlyReentrancy.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainReadOnlyReentrancyHarness is Test {
    TrainReadOnlyReentrancy public pool;
    address public lpProvider = address(0x1111);
    uint256 public constant INITIAL_LENDING_RESERVE = 10 ether;
    uint256 public constant LP_SEED = 2 ether;
    uint256 public constant ATTACKER_BUDGET = 9 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        pool = new TrainReadOnlyReentrancy();
        pool.fundLendingReserve{value: INITIAL_LENDING_RESERVE}();
        vm.deal(lpProvider, LP_SEED);
        vm.prank(lpProvider);
        pool.addLiquidity{value: LP_SEED}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (pool.lendingReserve() < INITIAL_LENDING_RESERVE && pool.lendingReserve() < INITIAL_LENDING_RESERVE - 1 ether) {
            emit SecurityInvariantBreached(
                "READ_ONLY_REENTRANCY_PRICE_INFLATION",
                INITIAL_LENDING_RESERVE - pool.lendingReserve()
            );
            return;
        }
        revert("EXPLOIT_FAILED: Lending reserve remained adequately collateralized");
    }

    receive() external payable {}
}
