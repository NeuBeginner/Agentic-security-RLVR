// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainERC721CallbackLender} from "../src/TrainERC721CallbackLender.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainERC721CallbackLenderHarness is Test {
    TrainERC721CallbackLender public lender;
    uint256 public constant INITIAL_POOL = 10 ether;
    uint256 public constant MAX_SINGLE_BORROW = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        lender = new TrainERC721CallbackLender{value: INITIAL_POOL}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(lender));
        exploit.runExploit();

        if (address(lender).balance < INITIAL_POOL - MAX_SINGLE_BORROW) {
            emit SecurityInvariantBreached(
                "ERC721_SAFE_MINT_REENTRANCY_DRAIN",
                (INITIAL_POOL - MAX_SINGLE_BORROW) - address(lender).balance
            );
            return;
        }
        revert("EXPLOIT_FAILED: Position mint cap enforced");
    }

    receive() external payable {}
}
