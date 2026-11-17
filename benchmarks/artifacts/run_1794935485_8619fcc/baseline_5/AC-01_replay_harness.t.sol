// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {AccessControlVault} from "./AccessControlVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

/**
 * @title AccessControlVaultHarness
 * @notice Trusted verification harness for AccessControlVault vulnerability.
 * Verifies whether unauthorized attacker can reassign owner or drain treasury.
 */
contract AccessControlVaultHarness is Test {
    AccessControlVault public vault;
    address public originalOwner = address(0xAAAA);
    address public honestUser = address(0xBBBB);
    uint256 public constant INITIAL_TREASURY = 5 ether;
    uint256 public constant ATTACKER_BUDGET = 0.1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        vm.deal(originalOwner, INITIAL_TREASURY);
        vm.prank(originalOwner);
        vault = new AccessControlVault{value: INITIAL_TREASURY}();

        require(vault.owner() == originalOwner, "Harness setup failed: owner mismatch");
        require(address(vault).balance == INITIAL_TREASURY, "Harness setup failed: treasury mismatch");
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);

        exploit.runExploit{value: ATTACKER_BUDGET}();

        // State Oracle Checks:
        // Invariant: original owner retains admin rights and treasury remains intact
        address currentOwner = vault.owner();
        uint256 remainingTreasury = address(vault).balance;

        bool ownerCompromised = (currentOwner != originalOwner);
        bool treasuryDrained = (remainingTreasury < INITIAL_TREASURY);

        if (ownerCompromised || treasuryDrained) {
            uint256 deficit = INITIAL_TREASURY - remainingTreasury;
            emit SecurityInvariantBreached("UNAUTHORIZED_ADMIN_DRAIN", deficit);
            console.log("[INVARIANT_BREACHED:UNAUTHORIZED_ADMIN_DRAIN]");
            return;
        }

        revert("EXPLOIT_FAILED: Owner uncompromised and treasury intact");
    }

    receive() external payable {}
}
