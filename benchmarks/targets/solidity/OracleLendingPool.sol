// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockSpotOracle
 * @notice Simplified spot price oracle readable without TWAP smoothing.
 */
contract MockSpotOracle {
    uint256 public price; // scaled by 1e18 (e.g. 1 Token = X ETH)

    constructor(uint256 _initialPrice) {
        price = _initialPrice;
    }

    function setPrice(uint256 _newPrice) external {
        price = _newPrice;
    }

    function getSpotPrice() external view returns (uint256) {
        return price;
    }
}

/**
 * @title OracleLendingPool
 * @notice Vulnerable lending pool relying on spot oracle price without TWAP or sanity checks.
 * Allows attacker to inflate collateral valuation in a single tx and drain pool funds.
 */
contract OracleLendingPool {
    MockSpotOracle public oracle;
    mapping(address => uint256) public collateralBalances;
    mapping(address => uint256) public borrowedBalances;

    event CollateralDeposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);

    constructor(address _oracle) payable {
        oracle = MockSpotOracle(_oracle);
    }

    function depositCollateral() external payable {
        collateralBalances[msg.sender] += msg.value;
        emit CollateralDeposited(msg.sender, msg.value);
    }

    // VULNERABILITY: Spot oracle manipulation allows over-borrowing against manipulated collateral value
    function borrow(uint256 amount) external {
        uint256 collateral = collateralBalances[msg.sender];
        uint256 price = oracle.getSpotPrice(); // Vulnerable to instant flash manipulation
        uint256 maxBorrow = (collateral * price) / 1e18;

        require(borrowedBalances[msg.sender] + amount <= maxBorrow, "Exceeds borrow allowance");
        require(address(this).balance >= amount, "Insufficient pool liquidity");

        borrowedBalances[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
        emit Borrowed(msg.sender, amount);
    }

    receive() external payable {}
}
