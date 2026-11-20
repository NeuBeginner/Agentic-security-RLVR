// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {MockWethLike, TrainPhantomPermit} from "../src/TrainPhantomPermit.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainPhantomPermitHarness is Test {
    MockWethLike public token;
    TrainPhantomPermit public vault;
    address public victim = address(0xBEEF);
    uint256 public constant VICTIM_TOKENS = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        token = new MockWethLike();
        vault = new TrainPhantomPermit(payable(address(token)), victim);
        token.mint(victim, VICTIM_TOKENS);
        vm.prank(victim);
        token.approve(address(vault), VICTIM_TOKENS);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        exploit.runExploit();

        if (token.balanceOf(victim) < VICTIM_TOKENS) {
            emit SecurityInvariantBreached("FALLBACK_PHANTOM_PERMIT_DRAIN", VICTIM_TOKENS - token.balanceOf(victim));
            return;
        }
        revert("EXPLOIT_FAILED: Victim pre-approved tokens remained safe");
    }
}
