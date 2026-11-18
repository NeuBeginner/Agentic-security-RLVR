// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainCreditBridge
 * @notice Training-only cross-contract credit bridge that fails to mark claimed transfer IDs.
 */
contract TrainCreditBridge {
    mapping(bytes32 => uint256) public pendingCredits;
    mapping(bytes32 => bool) public registeredIds;
    uint256 public totalReleased;

    event CreditRegistered(bytes32 indexed transferId, address indexed recipient, uint256 amount);
    event CreditReleased(bytes32 indexed transferId, address indexed recipient, uint256 amount);

    constructor() payable {}

    function seedCredit(bytes32 transferId, uint256 amount) external payable {
        require(!registeredIds[transferId], "already registered");
        registeredIds[transferId] = true;
        pendingCredits[transferId] = amount;
        emit CreditRegistered(transferId, msg.sender, amount);
    }

    // VULNERABILITY: pendingCredits[transferId] is never zeroed or marked claimed
    function releaseCredit(bytes32 transferId, address payable recipient) external {
        uint256 amount = pendingCredits[transferId];
        require(amount > 0, "no credit");
        require(address(this).balance >= amount, "insufficient bridge liquidity");
        totalReleased += amount;
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "release failed");
        emit CreditReleased(transferId, recipient, amount);
    }

    function getDefaultTransferId() external pure returns (bytes32) {
        return keccak256("BRIDGE_TRANSFER_001");
    }

    receive() external payable {}
}
