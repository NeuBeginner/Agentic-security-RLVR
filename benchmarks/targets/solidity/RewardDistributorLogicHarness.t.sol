// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {RewardDistributorLogic} from "./RewardDistributorLogic.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract RewardDistributorLogicHarness is Test {
    RewardDistributorLogic public distributor;
    uint256 public constant INITIAL_POOL = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        distributor = new RewardDistributorLogic{value: INITIAL_POOL}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(distributor));
        
        // Award attacker 1 point (entitles only to 0.1 ether)
        distributor.awardPoints(address(exploit), 1);

        exploit.runExploit();

        // Invariant: Pool must retain at least INITIAL_POOL - 0.1 ether
        if (address(distributor).balance < INITIAL_POOL - 0.1 ether) {
            uint256 deficit = INITIAL_POOL - address(distributor).balance;
            emit SecurityInvariantBreached("STATE_ACCOUNTING_INCONSISTENCY", deficit);
            console.log("[INVARIANT_BREACHED:STATE_ACCOUNTING_INCONSISTENCY]");
            return;
        }

        revert("EXPLOIT_FAILED: Accounting consistency upheld");
    }

    receive() external payable {}
}
