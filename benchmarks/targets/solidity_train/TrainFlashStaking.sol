// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainFlashStaking
 * @notice Training-only staking pool granting instant rewards without lockup duration.
 */
contract TrainFlashStaking {
    mapping(address => uint256) public stakedBalance;
    mapping(address => bool) public hasClaimed;
    uint256 public totalStaked;

    constructor() payable {}

    function enterStake() external payable {
        require(msg.value > 0, "zero");
        stakedBalance[msg.sender] += msg.value;
        totalStaked += msg.value;
    }

    // VULNERABILITY: Instantaneous balance snapshot without lockup allows flash-deposit drain
    function harvestInstantBonus() external {
        require(!hasClaimed[msg.sender], "already claimed");
        uint256 stake = stakedBalance[msg.sender];
        require(stake > 0, "no stake");
        hasClaimed[msg.sender] = true;
        uint256 bonus = stake / 2; // 50% instant bonus
        require(address(this).balance >= totalStaked + bonus, "insufficient reserve");
        (bool ok, ) = msg.sender.call{value: bonus}("");
        require(ok, "bonus transfer failed");
    }

    function exitStake() external {
        uint256 stake = stakedBalance[msg.sender];
        require(stake > 0, "no stake");
        stakedBalance[msg.sender] = 0;
        totalStaked -= stake;
        (bool ok, ) = msg.sender.call{value: stake}("");
        require(ok, "exit failed");
    }

    receive() external payable {}
}
