// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {LendingLiquidation} from "./LendingLiquidation.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract LendingLiquidationHarness is Test {
    LendingLiquidation public lending;
    address public borrower = address(0xDDDD);
    uint256 public constant BORROWER_COLLATERAL = 8 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        lending = new LendingLiquidation();
        vm.deal(borrower, BORROWER_COLLATERAL);
        vm.prank(borrower);
        lending.openPosition{value: BORROWER_COLLATERAL}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(lending));
        exploit.runExploit();

        // Invariant: Liquidator must not be able to seize collateral without debt repayment
        if (address(lending).balance < BORROWER_COLLATERAL) {
            uint256 deficit = BORROWER_COLLATERAL - address(lending).balance;
            emit SecurityInvariantBreached("LIQUIDATION_ACCOUNTING_DEFECT", deficit);
            console.log("[INVARIANT_BREACHED:LIQUIDATION_ACCOUNTING_DEFECT]");
            return;
        }

        revert("EXPLOIT_FAILED: Collateral accounting preserved");
    }

    receive() external payable {}
}
