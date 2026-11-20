// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainStaleDebtIndex} from "../src/TrainStaleDebtIndex.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainStaleDebtIndexHarness is Test {
    TrainStaleDebtIndex public pool;
    uint256 public constant INITIAL_POOL = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        pool = new TrainStaleDebtIndex{value: INITIAL_POOL}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(pool).balance < INITIAL_POOL) {
            emit SecurityInvariantBreached("STALE_DEBT_ACCRUAL_DRAIN", INITIAL_POOL - address(pool).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Lending pool remained solvent");
    }

    receive() external payable {}
}
