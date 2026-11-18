// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainAdminTreasury
 * @notice Training-only treasury with unprotected governance transfer.
 */
contract TrainAdminTreasury {
    address public governance;

    event GovernanceChanged(address indexed previousGov, address indexed newGov);
    event TreasurySwept(address indexed to, uint256 amount);

    constructor() payable {
        governance = msg.sender;
    }

    // VULNERABILITY: Missing onlyGovernance check
    function updateGovernance(address newGovernance) external {
        require(newGovernance != address(0), "zero address");
        address old = governance;
        governance = newGovernance;
        emit GovernanceChanged(old, newGovernance);
    }

    function sweepTreasury(address payable recipient) external {
        require(msg.sender == governance, "not governance");
        uint256 bal = address(this).balance;
        (bool ok, ) = recipient.call{value: bal}("");
        require(ok, "sweep failed");
        emit TreasurySwept(recipient, bal);
    }

    receive() external payable {}
}
