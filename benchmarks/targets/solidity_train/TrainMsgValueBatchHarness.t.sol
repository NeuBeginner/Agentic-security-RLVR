// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainMsgValueBatch} from "../src/TrainMsgValueBatch.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainMsgValueBatchHarness is Test {
    TrainMsgValueBatch public vault;
    address public saver = address(0x5A7E);
    uint256 public constant SAVER_DEPOSIT = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainMsgValueBatch();
        vm.deal(saver, SAVER_DEPOSIT);
        vm.prank(saver);
        vault.depositSingle{value: SAVER_DEPOSIT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(vault).balance < vault.deposits(saver)) {
            uint256 deficit = vault.deposits(saver) - address(vault).balance;
            emit SecurityInvariantBreached("MSG_VALUE_LOOP_REUSE_DRAIN", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Batch deposit accounting remained solvent");
    }

    receive() external payable {}
}
