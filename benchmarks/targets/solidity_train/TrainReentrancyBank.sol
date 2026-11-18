// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainReentrancyBank
 * @notice Training-only ETH bank with Checks-Effects-Interactions violation in cashOut.
 */
contract TrainReentrancyBank {
    mapping(address => uint256) public ledger;

    event Deposited(address indexed account, uint256 amount);
    event CashedOut(address indexed account, uint256 amount);

    function depositFunds() external payable {
        require(msg.value > 0, "zero");
        ledger[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // VULNERABILITY: External call before state update
    function cashOut() external {
        uint256 amount = ledger[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        ledger[msg.sender] = 0;
        emit CashedOut(msg.sender, amount);
    }
}
