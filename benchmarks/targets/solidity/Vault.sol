// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableVault
 * @notice Simulates a DeFi lending/staking vault containing a classic 
 * Checks-Effects-Interactions (Reentrancy) flaw in withdrawAll().
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be positive");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdrawAll() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");

        // VULNERABILITY: External interaction before state update (Reentrancy vector)
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
        totalDeposits -= balance;
        emit Withdrawal(msg.sender, balance);
    }

    function getVaultBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
