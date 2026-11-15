// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BridgeLedger
 * @notice Internal ledger tracking deposits across chains.
 */
contract BridgeLedger {
    mapping(address => uint256) public credits;

    function addCredit(address user, uint256 amount) external {
        credits[user] += amount;
    }

    function spendCredit(address user, uint256 amount) external {
        require(credits[user] >= amount, "Insufficient credit");
        credits[user] -= amount;
    }
}

/**
 * @title CrossContractBridge
 * @notice Vulnerable bridge where release updates external token transfer
 * but forgets to notify the BridgeLedger, desynchronizing cross-contract state.
 */
contract CrossContractBridge {
    BridgeLedger public ledger;

    event TokensReleased(address indexed recipient, uint256 amount);

    constructor(address _ledger) payable {
        ledger = BridgeLedger(_ledger);
    }

    // VULNERABILITY: State desynchronization - releases funds without calling ledger.spendCredit()
    function releaseBridgedTokens(address payable recipient, uint256 amount) external {
        require(address(this).balance >= amount, "Insufficient bridge liquidity");
        require(ledger.credits(recipient) >= amount, "No ledger credit");

        // FLAW: Missing ledger.spendCredit(recipient, amount);
        recipient.transfer(amount);
        emit TokensReleased(recipient, amount);
    }

    receive() external payable {}
}
