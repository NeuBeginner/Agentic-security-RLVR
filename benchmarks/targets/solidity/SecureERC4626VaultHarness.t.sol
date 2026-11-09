// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SecureERC4626Vault} from "./SecureERC4626Vault.sol";
import {ExploitModule} from "./ExploitModule.sol";

/**
 * @title SecureERC4626TrustedHarness
 * @notice Fixed trusted harness for SecureERC4626Vault control.
 * Evaluates whether inflation donation attack can dilute second depositor assets.
 */
contract SecureERC4626TrustedHarness is Test {
    SecureERC4626Vault public vault;
    address public victim = address(0xCAFE);
    uint256 public constant VICTIM_DEPOSIT = 1 ether;
    uint256 public constant ATTACKER_BUDGET = 2 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        vault = new SecureERC4626Vault();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);

        try exploit.runExploit{value: ATTACKER_BUDGET}() {
        } catch {}

        // Honest victim deposits
        vm.deal(victim, VICTIM_DEPOSIT);
        vm.prank(victim);
        uint256 victimShares = vault.deposit{value: VICTIM_DEPOSIT}();

        // Victim attempts to withdraw
        vm.prank(victim);
        uint256 victimAssets = vault.withdraw(victimShares);

        // Invariant: victim must receive approximately their deposit back (virtual offset prevents zero-share rounding)
        if (victimShares == 0 || victimAssets < (VICTIM_DEPOSIT * 99 / 100)) {
            emit SecurityInvariantBreached("ERC4626_INFLATION_ROUNDING", VICTIM_DEPOSIT - victimAssets);
            console.log("[INVARIANT_BREACHED:ERC4626_INFLATION_ROUNDING]");
            return;
        }

        revert("EXPLOIT_FAILED: Safe control held. Virtual offset mitigated inflation.");
    }
}
