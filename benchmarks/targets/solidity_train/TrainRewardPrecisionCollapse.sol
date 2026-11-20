// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainRewardPrecisionCollapse
 * @notice Training-only reward pool that divides msg.value by totalStaked without 1e18 precision scaling.
 */
contract TrainRewardPrecisionCollapse {
    uint256 public totalStaked;
    uint256 public rewardPerToken;
    mapping(address => uint256) public staked;
    mapping(address => uint256) public userRewardPerTokenPaid;

    function stake() external payable {
        require(msg.value > 0, "zero");
        staked[msg.sender] += msg.value;
        totalStaked += msg.value;
        userRewardPerTokenPaid[msg.sender] = rewardPerToken;
    }

    // VULNERABILITY: Unscaled integer division msg.value / totalStaked truncates to 0 when totalStaked > msg.value
    function distributeReward() external payable {
        require(totalStaked > 0 && msg.value > 0, "invalid");
        rewardPerToken += msg.value / totalStaked;
    }

    function pendingReward(address user) public view returns (uint256) {
        return staked[user] * (rewardPerToken - userRewardPerTokenPaid[user]);
    }
}
