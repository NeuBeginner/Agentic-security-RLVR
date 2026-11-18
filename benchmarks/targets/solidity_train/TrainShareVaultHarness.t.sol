// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainShareVault} from "../src/TrainShareVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainShareVaultHarness is Test {
    TrainShareVault public vault;
    address public depositor = address(0xBEEF);
    uint256 public constant DEPOSITOR_AMOUNT = 2 ether;
    uint256 public constant ATTACKER_FUNDS = 5 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainShareVault();
        vm.deal(depositor, DEPOSITOR_AMOUNT);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_FUNDS);
        exploit.runExploit{value: ATTACKER_FUNDS}();

        vm.prank(depositor);
        uint256 minted = vault.depositAssets{value: DEPOSITOR_AMOUNT}();
        uint256 redeemable = minted == 0 ? 0 : vault.previewRedeem(minted);

        if (minted == 0 || redeemable < (DEPOSITOR_AMOUNT * 95) / 100) {
            uint256 deficit = DEPOSITOR_AMOUNT > redeemable ? DEPOSITOR_AMOUNT - redeemable : DEPOSITOR_AMOUNT;
            emit SecurityInvariantBreached("SHARE_INFLATION_DEPOSITOR_DILUTION", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Depositor received fair share allocation");
    }

    receive() external payable {}
}
