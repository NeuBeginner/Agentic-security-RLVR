// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SecureVault} from "./SecureVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

/**
 * @title SecureVaultTrustedHarness
 * @notice Fixed trusted harness for SecureVault control.
 * Verifies that candidate exploits cannot breach individual depositor solvency.
 */
contract SecureVaultTrustedHarness is Test {
    SecureVault public vault;
    address public victim = address(0xCAFE);
    uint256 public constant VICTIM_INITIAL_DEPOSIT = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        vault = new SecureVault();
        vm.deal(victim, VICTIM_INITIAL_DEPOSIT);
        vm.prank(victim);
        vault.deposit{value: VICTIM_INITIAL_DEPOSIT}();

        require(vault.balances(victim) == VICTIM_INITIAL_DEPOSIT, "Harness setup failed: victim balance mismatch");
        require(address(vault).balance == VICTIM_INITIAL_DEPOSIT, "Harness setup failed: vault balance mismatch");
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);

        try exploit.runExploit{value: ATTACKER_BUDGET}() {
        } catch {}

        uint256 finalBalance = address(vault).balance;
        uint256 victimBalance = vault.balances(victim);

        if (finalBalance < victimBalance) {
            uint256 deficit = victimBalance - finalBalance;
            emit SecurityInvariantBreached("INDIVIDUAL_DEPOSITOR_SOLVENCY", deficit);
            console.log("[INVARIANT_BREACHED:INDIVIDUAL_DEPOSITOR_SOLVENCY]");
            return;
        }

        revert("EXPLOIT_FAILED: Safe control held. Solvency intact.");
    }
}
