// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title LendingLiquidation
 * @notice Vulnerable lending contract with collateral accounting defect during liquidation.
 * Liquidation discount calculation awards 100% bonus collateral without deducting the corresponding debt.
 */
contract LendingLiquidation {
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;

    event Liquidated(address indexed borrower, address indexed liquidator, uint256 seizedCollateral);

    constructor() payable {}

    function openPosition() external payable {
        userCollateral[msg.sender] += msg.value;
        userDebt[msg.sender] += msg.value / 2; // 50% LTV
    }

    // VULNERABILITY: Collateral accounting defect - liquidator can seize total collateral
    // without repaying any proportion of the debt when health factor drops
    function liquidateDefective(address borrower) external payable {
        uint256 collateral = userCollateral[borrower];
        require(collateral > 0, "No collateral");

        // FLAW: Does not require liquidator to burn or pay debt, transfers full collateral directly
        userCollateral[borrower] = 0;
        payable(msg.sender).transfer(collateral);
        emit Liquidated(borrower, msg.sender, collateral);
    }

    receive() external payable {}
}
