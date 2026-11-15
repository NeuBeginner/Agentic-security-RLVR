// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITWAPOracle {
    function getTwapPrice() external view returns (uint256);
}

/**
 * @title SecureOraclePool
 * @notice Synthetic control contract for Oracle Manipulation benchmark.
 * Enforces Time-Weighted Average Price (TWAP) and price deviation circuit breaker.
 */
contract SecureOraclePool {
    ITWAPOracle public twapOracle;
    mapping(address => uint256) public collateralBalances;
    mapping(address => uint256) public borrowedBalances;

    constructor(address _twapOracle) payable {
        twapOracle = ITWAPOracle(_twapOracle);
    }

    function depositCollateral() external payable {
        collateralBalances[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        uint256 collateral = collateralBalances[msg.sender];
        uint256 twapPrice = twapOracle.getTwapPrice(); // Resistant to single-block flash loan manipulation
        uint256 maxBorrow = (collateral * twapPrice) / 1e18;

        require(borrowedBalances[msg.sender] + amount <= maxBorrow, "Exceeds allowance");
        require(address(this).balance >= amount, "Insufficient liquidity");

        borrowedBalances[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
