// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PrecisionStakingPool
 * @notice Vulnerable pool with division before multiplication leading to severe rounding down to zero,
 * enabling fee bypass or precision loss exploit.
 */
contract PrecisionStakingPool {
    mapping(address => uint256) public userShares;
    uint256 public constant PRECISION_FACTOR = 1e18;
    uint256 public poolFeeTreasury;

    event SharesMinted(address user, uint256 shares);

    constructor() payable {}

    // VULNERABILITY: Division before multiplication truncates calculation to 0 for deposits < PRECISION_FACTOR
    function depositWithFee() external payable {
        require(msg.value > 0, "Zero deposit");

        // FLAW: (msg.value / 1e18) * 5 rounds to 0 for small amounts, bypassing fees completely
        uint256 fee = (msg.value / PRECISION_FACTOR) * 5; 
        uint256 effectiveDeposit = msg.value - fee;

        poolFeeTreasury += fee;
        userShares[msg.sender] += effectiveDeposit;
        emit SharesMinted(msg.sender, effectiveDeposit);
    }

    receive() external payable {}
}
