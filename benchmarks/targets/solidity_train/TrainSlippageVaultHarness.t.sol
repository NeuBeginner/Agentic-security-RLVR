// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainSlippageVault} from "../src/TrainSlippageVault.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainSlippageVaultHarness is Test {
    TrainSlippageVault public vault;
    address public victim = address(0xBEEF);
    uint256 public constant INITIAL_ETH = 10 ether;
    uint256 public constant INITIAL_TOKENS = 10_000 ether;
    uint256 public constant ATTACKER_BUDGET = 5 ether;
    uint256 public constant VICTIM_MIN_OUT = 3_000 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainSlippageVault{value: INITIAL_ETH}(INITIAL_TOKENS);
        vm.deal(victim, 5 ether);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        vm.prank(victim);
        uint256 received = vault.swapEthForTokens{value: 5 ether}(VICTIM_MIN_OUT);

        if (received < VICTIM_MIN_OUT) {
            emit SecurityInvariantBreached("UNPROTECTED_SLIPPAGE_SANDWICH", VICTIM_MIN_OUT - received);
            return;
        }
        revert("EXPLOIT_FAILED: Victim slippage tolerance respected");
    }

    receive() external payable {}
}
