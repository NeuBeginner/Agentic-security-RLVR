// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {FeeShareYieldVault} from "./FeeShareYieldVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract FeeShareYieldVaultHarness is Test {
    FeeShareYieldVault public vault;
    uint256 public constant INITIAL_YIELD = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        vault = new FeeShareYieldVault{value: INITIAL_YIELD}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        exploit.runExploit();

        // Invariant: Yield should not be drained by unauthorized arbitrary fee caller
        if (address(vault).balance < INITIAL_YIELD) {
            uint256 deficit = INITIAL_YIELD - address(vault).balance;
            emit SecurityInvariantBreached("BUSINESS_LOGIC_FEE_DRAIN", deficit);
            console.log("[INVARIANT_BREACHED:BUSINESS_LOGIC_FEE_DRAIN]");
            return;
        }

        revert("EXPLOIT_FAILED: Yield fees protected");
    }

    receive() external payable {}
}
