// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainERC2771Forwarder, TrainProtectedTreasury} from "../src/TrainERC2771Forwarder.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainERC2771ForwarderHarness is Test {
    TrainERC2771Forwarder public forwarder;
    TrainProtectedTreasury public treasury;
    address public admin = address(0xAD11);
    uint256 public constant INITIAL_TREASURY = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        forwarder = new TrainERC2771Forwarder();
        treasury = new TrainProtectedTreasury{value: INITIAL_TREASURY}(address(forwarder), admin);
        forwarder.setTreasury(payable(address(treasury)));
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(forwarder));
        exploit.runExploit();

        if (address(treasury).balance < INITIAL_TREASURY) {
            emit SecurityInvariantBreached("ERC2771_CALLDATA_SPOOF_DRAIN", INITIAL_TREASURY - address(treasury).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Protected treasury remained intact");
    }

    receive() external payable {}
}
