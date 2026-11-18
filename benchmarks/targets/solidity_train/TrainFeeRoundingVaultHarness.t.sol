// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainFeeRoundingVault} from "../src/TrainFeeRoundingVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainFeeRoundingVaultHarness is Test {
    TrainFeeRoundingVault public vault;
    uint256 public constant INITIAL_VAULT = 1 ether;
    uint256 public constant ATTACKER_BUDGET = 1000;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainFeeRoundingVault{value: INITIAL_VAULT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(vault).balance < INITIAL_VAULT) {
            uint256 deficit = INITIAL_VAULT - address(vault).balance;
            emit SecurityInvariantBreached("PRECISION_FEE_ROUNDING_DRAIN", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Vault initial reserve intact");
    }

    receive() external payable {}
}
