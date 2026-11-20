// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainCrossFuncVault
 * @notice Training-only vault vulnerable to cross-function reentrancy between withdraw and transferBalance.
 */
contract TrainCrossFuncVault {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function transferBalance(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    // VULNERABILITY: External call before zeroing balances[msg.sender] enables cross-function reentrancy
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, amount);
    }
}
