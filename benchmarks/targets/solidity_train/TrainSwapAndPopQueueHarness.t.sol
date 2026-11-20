// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainSwapAndPopQueue} from "../src/TrainSwapAndPopQueue.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainSwapAndPopQueueHarness is Test {
    TrainSwapAndPopQueue public queueContract;
    address public victim = address(0x5A7E);
    uint256 public constant VICTIM_DEPOSIT = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 2 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        queueContract = new TrainSwapAndPopQueue();
        vm.deal(victim, VICTIM_DEPOSIT);
        vm.prank(victim);
        queueContract.join{value: VICTIM_DEPOSIT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(queueContract));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(queueContract).balance < VICTIM_DEPOSIT) {
            emit SecurityInvariantBreached(
                "ARRAY_SWAP_AND_POP_DESYNC",
                VICTIM_DEPOSIT - address(queueContract).balance
            );
            return;
        }
        revert("EXPLOIT_FAILED: Queue deposits remained solvent");
    }

    receive() external payable {}
}
