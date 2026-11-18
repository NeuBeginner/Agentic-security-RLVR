// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainCreditBridge} from "../src/TrainCreditBridge.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainCreditBridgeHarness is Test {
    TrainCreditBridge public bridge;
    uint256 public constant BRIDGE_LIQUIDITY = 6 ether;
    uint256 public constant SINGLE_CREDIT = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        bridge = new TrainCreditBridge{value: BRIDGE_LIQUIDITY}();
        bytes32 tid = bridge.getDefaultTransferId();
        bridge.seedCredit(tid, SINGLE_CREDIT);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(bridge));
        exploit.runExploit();

        if (address(bridge).balance < BRIDGE_LIQUIDITY - SINGLE_CREDIT) {
            uint256 deficit = (BRIDGE_LIQUIDITY - SINGLE_CREDIT) - address(bridge).balance;
            emit SecurityInvariantBreached("CROSS_CONTRACT_CREDIT_REPLAY", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Bridge released at most one authorized credit");
    }

    receive() external payable {}
}
