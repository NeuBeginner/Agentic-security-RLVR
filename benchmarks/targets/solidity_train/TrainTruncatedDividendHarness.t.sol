// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainTruncatedDividend} from "../src/TrainTruncatedDividend.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainTruncatedDividendHarness is Test {
    TrainTruncatedDividend public vault;
    uint256 public constant INITIAL_VAULT = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainTruncatedDividend{value: INITIAL_VAULT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        exploit.runExploit();

        if (address(vault).balance < INITIAL_VAULT) {
            emit SecurityInvariantBreached("INTEGER_TRUNCATION_OVERFLOW", INITIAL_VAULT - address(vault).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Dividend vault remained intact");
    }

    receive() external payable {}
}
