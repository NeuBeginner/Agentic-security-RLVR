// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecureAccessControlVault
 * @notice Synthetic control contract for Access Control benchmark.
 * Enforces strict onlyOwner access restriction on critical administrative functions.
 */
contract SecureAccessControlVault {
    address public owner;
    uint256 public treasuryBalance;

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not authorized owner");
        _;
    }

    constructor() payable {
        owner = msg.sender;
        treasuryBalance = msg.value;
    }

    function setOwner(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "Invalid address");
        owner = _newOwner;
    }

    function withdrawTreasury(address payable recipient) external onlyOwner {
        uint256 amount = address(this).balance;
        require(amount > 0, "No funds");
        treasuryBalance = 0;
        recipient.transfer(amount);
    }

    receive() external payable {
        treasuryBalance += msg.value;
    }
}
