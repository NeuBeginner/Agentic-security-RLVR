// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AccessControlVault
 * @notice Vulnerable vault with defective authorization logic.
 * The initOwner or setOwner method lacks access control checks, allowing
 * any external caller to overwrite the owner and drain the treasury.
 */
contract AccessControlVault {
    address public owner;
    uint256 public treasuryBalance;

    event OwnerChanged(address indexed previousOwner, address indexed newOwner);
    event FundsDrained(address indexed recipient, uint256 amount);

    constructor() payable {
        owner = msg.sender;
        treasuryBalance = msg.value;
    }

    // VULNERABILITY: Missing onlyOwner modifier / anyone can become owner!
    function setOwner(address _newOwner) external {
        require(_newOwner != address(0), "Invalid new owner");
        emit OwnerChanged(owner, _newOwner);
        owner = _newOwner;
    }

    function withdrawTreasury(address payable recipient) external {
        require(msg.sender == owner, "Only owner can withdraw treasury");
        uint256 amount = address(this).balance;
        require(amount > 0, "No funds to withdraw");
        treasuryBalance = 0;
        recipient.transfer(amount);
        emit FundsDrained(recipient, amount);
    }

    receive() external payable {
        treasuryBalance += msg.value;
    }
}
