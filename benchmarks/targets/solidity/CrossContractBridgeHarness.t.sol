// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {CrossContractBridge, BridgeLedger} from "./CrossContractBridge.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract CrossContractBridgeHarness is Test {
    BridgeLedger public ledger;
    CrossContractBridge public bridge;
    uint256 public constant BRIDGE_LIQUIDITY = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        ledger = new BridgeLedger();
        bridge = new CrossContractBridge{value: BRIDGE_LIQUIDITY}(address(ledger));
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(bridge));
        // Credit 1 ether to attacker once
        ledger.addCredit(address(exploit), 1 ether);

        exploit.runExploit();

        // Invariant: Attacker should not be able to drain more than their 1 ether credit
        if (address(bridge).balance < BRIDGE_LIQUIDITY - 1 ether) {
            uint256 deficit = (BRIDGE_LIQUIDITY - 1 ether) - address(bridge).balance;
            emit SecurityInvariantBreached("CROSS_CONTRACT_DESYNCHRONIZATION", deficit);
            console.log("[INVARIANT_BREACHED:CROSS_CONTRACT_DESYNCHRONIZATION]");
            return;
        }

        revert("EXPLOIT_FAILED: Bridge ledger synchronized");
    }

    receive() external payable {}
}
