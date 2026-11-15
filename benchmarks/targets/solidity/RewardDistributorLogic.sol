// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RewardDistributorLogic
 * @notice Vulnerable distributor where claims check points without properly decrementing them,
 * allowing repetitive claims and depleting contract rewards.
 */
contract RewardDistributorLogic {
    mapping(address => uint256) public userPoints;
    uint256 public totalRewardPool;

    event PointsAwarded(address indexed user, uint256 points);
    event RewardPaid(address indexed user, uint256 amount);

    constructor() payable {
        totalRewardPool = msg.value;
    }

    function awardPoints(address user, uint256 points) external {
        userPoints[user] += points;
        emit PointsAwarded(user, points);
    }

    // VULNERABILITY: State inconsistency - reads userPoints but fails to reduce or reset them upon claim!
    function claimPointsReward() external {
        uint256 points = userPoints[msg.sender];
        require(points > 0, "No reward points");
        
        uint256 payout = points * 0.1 ether;
        require(address(this).balance >= payout, "Insufficient pool reserves");

        // FLAW: Missing userPoints[msg.sender] = 0;
        payable(msg.sender).transfer(payout);
        emit RewardPaid(msg.sender, payout);
    }

    receive() external payable {}
}
