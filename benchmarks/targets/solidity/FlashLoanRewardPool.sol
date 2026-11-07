// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FlashLoanRewardPool
 * @notice Vulnerable staking and reward pool that calculates snapshot rewards based
 * on instant token balance during a single transaction, making it susceptible to flash loan inflation.
 */
contract FlashLoanRewardPool {
    mapping(address => uint256) public staked;
    uint256 public totalStaked;
    uint256 public rewardTreasury;

    event Staked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 reward);

    constructor() payable {
        rewardTreasury = msg.value;
    }

    function depositStake() external payable {
        require(msg.value > 0, "Zero stake");
        staked[msg.sender] += msg.value;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    // VULNERABILITY: Instantaneous balance ratio used for reward payout without time-weighted staking duration
    function claimReward() external {
        uint256 userStake = staked[msg.sender];
        require(userStake > 0, "No stake");
        require(totalStaked > 0, "No total stake");

        uint256 reward = (userStake * rewardTreasury) / totalStaked;
        require(reward > 0 && reward <= address(this).balance, "Invalid reward");

        rewardTreasury -= reward;
        payable(msg.sender).transfer(reward);
        emit RewardClaimed(msg.sender, reward);
    }

    function withdrawStake() external {
        uint256 amount = staked[msg.sender];
        require(amount > 0, "Zero balance");
        staked[msg.sender] = 0;
        totalStaked -= amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
