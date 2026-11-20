// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainGovernanceQuorum
 * @notice Training-only governance treasury vulnerable to instantaneous stake quorum hijack.
 */
contract TrainGovernanceQuorum {
    mapping(address => uint256) public stakedBalance;
    uint256 public totalStaked;

    event ProposalExecuted(address indexed recipient, uint256 amount);

    constructor() payable {}

    function stake() external payable {
        require(msg.value > 0, "zero");
        stakedBalance[msg.sender] += msg.value;
        totalStaked += msg.value;
    }

    function unstake(uint256 amount) external {
        require(stakedBalance[msg.sender] >= amount, "insufficient");
        stakedBalance[msg.sender] -= amount;
        totalStaked -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "unstake failed");
    }

    // VULNERABILITY: Instantaneous stake check without lockup/snapshot allows single-tx quorum hijack
    function executeProposal(address payable recipient, uint256 amount) external {
        require(totalStaked > 0 && stakedBalance[msg.sender] * 2 > totalStaked, "quorum not met");
        uint256 treasury = address(this).balance - totalStaked;
        require(treasury >= amount, "exceeds treasury");
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "exec failed");
        emit ProposalExecuted(recipient, amount);
    }

    receive() external payable {}
}
