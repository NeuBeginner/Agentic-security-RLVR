// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockChainlinkFeed {
    int256 public answer;
    uint256 public updatedAt;

    function setPrice(int256 _answer, uint256 _updatedAt) external {
        answer = _answer;
        updatedAt = _updatedAt;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (1, answer, updatedAt, updatedAt, 1);
    }
}

/**
 * @title TrainStaleOracleFeed
 * @notice Training-only lending pool that accepts stale oracle timestamps without staleness check.
 */
contract TrainStaleOracleFeed {
    MockChainlinkFeed public immutable feed;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _feed) payable {
        feed = MockChainlinkFeed(_feed);
    }

    function postCollateral() external payable {
        require(msg.value > 0, "zero");
        collateral[msg.sender] += msg.value;
    }

    // VULNERABILITY: Ignores updatedAt staleness from latestRoundData()
    function borrow(uint256 amount) external {
        (, int256 price, , , ) = feed.latestRoundData();
        require(price > 0, "bad price");
        uint256 maxBorrow = (collateral[msg.sender] * uint256(price)) / 1e18;
        require(debt[msg.sender] + amount <= maxBorrow, "undercollateralized");
        require(address(this).balance >= amount, "empty pool");
        debt[msg.sender] += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "borrow failed");
    }

    receive() external payable {}
}
