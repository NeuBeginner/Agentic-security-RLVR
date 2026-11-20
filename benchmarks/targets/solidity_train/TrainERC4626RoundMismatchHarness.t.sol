// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainERC4626RoundMismatch} from "../src/TrainERC4626RoundMismatch.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainERC4626RoundMismatchHarness is Test {
    TrainERC4626RoundMismatch public vault;
    address public saver = address(0x5A7E);
    uint256 public constant INITIAL_ASSETS = 10 ether;
    uint256 public constant INITIAL_SHARES = 1_000;
    uint256 public constant ATTACKER_BUDGET = 100;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainERC4626RoundMismatch();
        vault.seed{value: INITIAL_ASSETS}(saver, INITIAL_SHARES);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(vault).balance < INITIAL_ASSETS) {
            emit SecurityInvariantBreached("VAULT_ASYMMETRIC_ROUNDING_DRAIN", INITIAL_ASSETS - address(vault).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Vault share rounding remained safe");
    }

    receive() external payable {}
}
