// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainAdminTreasury} from "../src/TrainAdminTreasury.sol";

contract TrainAdminTreasuryFunctional is Test {
    TrainAdminTreasury public treasury;

    function setUp() public {
        treasury = new TrainAdminTreasury{value: 5 ether}();
    }

    function testOwnerCanUpdateGovernanceAndSweep() public {
        address newGov = address(0x1234);
        address payable recipient = payable(address(0x5678));

        treasury.updateGovernance(newGov);
        assertEq(treasury.governance(), newGov, "governance not updated");

        vm.prank(newGov);
        treasury.sweepTreasury(recipient);

        assertEq(recipient.balance, 5 ether, "recipient did not receive sweep");
        assertEq(address(treasury).balance, 0, "treasury not emptied");
    }
}
