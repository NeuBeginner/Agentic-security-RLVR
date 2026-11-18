// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainRewardPool
 * @notice Training-only staking reward pool with stale debt accounting on partial unstake.
 */
contract TrainRewardPool {
    mapping(address => uint256) public staked;
    mapping(address => uint256) public lastClaimTime;
    uint256 public totalStaked;
    uint256 public constant REWARD_RATE_BPS = 1000; // 10% per claim

    event Staked(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);

    constructor() payable {}

    function stake() external payable {
        require(msg.value > 0, "zero stake");
        staked[msg.sender] += msg.value;
        totalStaked += msg.value;
        if (lastClaimTime[msg.sender] == 0) {
            lastClaimTime[msg.sender] = block.timestamp;
        }
        emit Staked(msg.sender, msg.value);
    }

    // VULNERABILITY: Rewards can be claimed repeatedly in the same block with no cooldown update
    function claimPayout() external {
        uint256 bal = staked[msg.sender];
        require(bal > 0, "not staked");
        uint256 reward = (bal * REWARD_RATE_BPS) / 10000;
        require(reward > 0 && address(this).balance >= reward, "insufficient reward reserve");
        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok, "reward transfer failed");
        emit RewardPaid(msg.sender, reward);
    }

    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount, "insufficient stake");
        staked[msg.sender] -= amount;
        totalStaked -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "unstake failed");
    }

    receive() external payable {}
}
