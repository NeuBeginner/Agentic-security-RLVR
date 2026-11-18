// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainAdminTreasury} from "../src/TrainAdminTreasury.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainAdminTreasuryHarness is Test {
    TrainAdminTreasury public treasury;
    uint256 public constant TREASURY_FUNDS = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        treasury = new TrainAdminTreasury{value: TREASURY_FUNDS}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(treasury));
        exploit.runExploit();

        if (address(treasury).balance < TREASURY_FUNDS || treasury.governance() != address(this)) {
            uint256 deficit = TREASURY_FUNDS - address(treasury).balance;
            emit SecurityInvariantBreached("UNAUTHORIZED_GOVERNANCE_DRAIN", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Governance and treasury funds remained intact");
    }

    receive() external payable {}
}
