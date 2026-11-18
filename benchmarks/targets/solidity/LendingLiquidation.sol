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

    /// @notice The borrowers that opened a position.
    /// @dev The registry is a **public** fact of the contract: a liquidator
    /// reads it on chain instead of guessing an address that is not part of the
    /// state of the contract. The identity of the borrower is a fact of the
    /// state - never a constant that the exploit has to know in advance.
    address[] public borrowers;

    event Liquidated(address indexed borrower, address indexed liquidator, uint256 seizedCollateral);

    constructor() payable {}

    function openPosition() external payable {
        userCollateral[msg.sender] += msg.value;
        userDebt[msg.sender] += msg.value / 2; // 50% LTV
        borrowers.push(msg.sender);
    }

    /// @notice The borrowers that opened a position.
    /// @return The list of the borrowers, in the order they opened their position.
    function getBorrowers() external view returns (address[] memory) {
        return borrowers;
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
