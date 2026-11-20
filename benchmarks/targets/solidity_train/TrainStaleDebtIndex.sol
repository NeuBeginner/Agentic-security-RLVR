// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainStaleDebtIndex
 * @notice Training-only lending pool where withdrawCollateral checks stale cachedDebt instead of liveDebt.
 */
contract TrainStaleDebtIndex {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public liveDebt;
    mapping(address => uint256) public cachedDebt;

    constructor() payable {}

    function depositCollateral() external payable {
        require(msg.value > 0, "zero");
        collateral[msg.sender] += msg.value;
    }

    // VULNERABILITY: Updates liveDebt but leaves cachedDebt stale until repay()
    function borrow(uint256 amount) external {
        require(amount > 0, "zero");
        require((collateral[msg.sender] * 80) / 100 >= liveDebt[msg.sender] + amount, "exceeds ltv");
        liveDebt[msg.sender] += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "borrow failed");
    }

    function repay() external payable {
        require(msg.value > 0 && liveDebt[msg.sender] >= msg.value, "bad repay");
        liveDebt[msg.sender] -= msg.value;
        cachedDebt[msg.sender] = liveDebt[msg.sender];
    }

    // Checks stale cachedDebt[msg.sender] instead of liveDebt[msg.sender]
    function withdrawCollateral(uint256 amount) external {
        require(collateral[msg.sender] >= amount && amount > 0, "bad amount");
        uint256 remainingCol = collateral[msg.sender] - amount;
        require((remainingCol * 80) / 100 >= cachedDebt[msg.sender], "undercollateralized");
        collateral[msg.sender] = remainingCol;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
    }

    receive() external payable {}
}
