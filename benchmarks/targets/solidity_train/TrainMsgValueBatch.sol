// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainMsgValueBatch
 * @notice Training-only batch deposit vault that reuses msg.value across loop iterations.
 */
contract TrainMsgValueBatch {
    mapping(address => uint256) public deposits;

    event BatchDeposited(uint256 count, uint256 totalCreditedEach);
    event Withdrawn(address indexed user, uint256 amount);

    function depositSingle() external payable {
        require(msg.value > 0, "zero");
        deposits[msg.sender] += msg.value;
    }

    // VULNERABILITY: msg.value is credited in full for every recipient in the loop
    function batchDeposit(address[] calldata recipients) external payable {
        require(msg.value > 0 && recipients.length > 0, "invalid");
        for (uint256 i = 0; i < recipients.length; i++) {
            deposits[recipients[i]] += msg.value;
        }
        emit BatchDeposited(recipients.length, msg.value);
    }

    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "empty");
        deposits[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
        emit Withdrawn(msg.sender, amount);
    }
}
