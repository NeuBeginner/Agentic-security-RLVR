// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainGovernanceQuorum} from "../src/TrainGovernanceQuorum.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainGovernanceQuorumHarness is Test {
    TrainGovernanceQuorum public gov;
    address public honestVoter = address(0xB0B);
    uint256 public constant INITIAL_TREASURY = 10 ether;
    uint256 public constant HONEST_STAKE = 1 ether;
    uint256 public constant ATTACKER_BUDGET = 2 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        gov = new TrainGovernanceQuorum{value: INITIAL_TREASURY}();
        vm.deal(honestVoter, HONEST_STAKE);
        vm.prank(honestVoter);
        gov.stake{value: HONEST_STAKE}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(gov));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        uint256 expectedMinBalance = INITIAL_TREASURY + gov.totalStaked();
        if (address(gov).balance < expectedMinBalance) {
            emit SecurityInvariantBreached("FLASH_GOVERNANCE_QUORUM_HIJACK", expectedMinBalance - address(gov).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Governance treasury remained intact");
    }

    receive() external payable {}
}
