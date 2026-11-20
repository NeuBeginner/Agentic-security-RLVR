// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainSelfLiquidationPool
 * @notice Training-only lending pool vulnerable to self-liquidation bonus drain without debt repayment.
 */
contract TrainSelfLiquidationPool {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    event Borrowed(address indexed user, uint256 amount);
    event Liquidated(address indexed borrower, address indexed liquidator, uint256 payout);

    constructor() payable {}

    function depositCollateral() external payable {
        require(msg.value > 0, "zero");
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        require(amount > 0, "zero");
        require((collateral[msg.sender] * 80) / 100 >= debt[msg.sender] + amount, "exceeds ltv");
        debt[msg.sender] += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "borrow failed");
        emit Borrowed(msg.sender, amount);
    }

    // VULNERABILITY: Allows self-liquidation with 20% bonus and clears debt without repayment
    function liquidate(address borrower) external {
        uint256 col = collateral[borrower];
        require(debt[borrower] > 0 && col > 0, "not liquidatable");
        uint256 payout = col + (col * 20) / 100;
        collateral[borrower] = 0;
        debt[borrower] = 0;
        require(address(this).balance >= payout, "insufficient pool");
        (bool ok, ) = msg.sender.call{value: payout}("");
        require(ok, "payout failed");
        emit Liquidated(borrower, msg.sender, payout);
    }

    receive() external payable {}
}
