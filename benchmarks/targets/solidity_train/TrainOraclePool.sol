// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockSpotFeed
 * @notice Mutable spot price feed without TWAP protection (training-only).
 */
contract MockSpotFeed {
    uint256 public spotPrice;

    constructor(uint256 initialPrice) {
        spotPrice = initialPrice;
    }

    function updateSpotPrice(uint256 newPrice) external {
        spotPrice = newPrice;
    }
}

/**
 * @title TrainOraclePool
 * @notice Training-only lending pool relying on manipulable spot oracle.
 */
contract TrainOraclePool {
    MockSpotFeed public feed;
    mapping(address => uint256) public collateralEth;
    mapping(address => uint256) public borrowedEth;

    constructor(address _feed) payable {
        feed = MockSpotFeed(_feed);
    }

    function postCollateral() external payable {
        require(msg.value > 0, "zero collateral");
        collateralEth[msg.sender] += msg.value;
    }

    function maxBorrowable(address user) public view returns (uint256) {
        // VULNERABILITY: Direct spot price multiplication without TWAP or bounds
        return (collateralEth[user] * feed.spotPrice()) / 1e18;
    }

    function borrowFromPool(uint256 amount) external {
        require(amount > 0 && amount <= address(this).balance, "bad amount");
        require(borrowedEth[msg.sender] + amount <= maxBorrowable(msg.sender), "undercollateralized");
        borrowedEth[msg.sender] += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "borrow transfer failed");
    }

    receive() external payable {}
}
