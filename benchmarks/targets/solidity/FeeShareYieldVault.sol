// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FeeShareYieldVault
 * @notice Business logic vulnerability: fee deduction formula calculates fee based on caller input
 * rather than verified internal protocol profit, allowing fee drain / reward dilution.
 */
contract FeeShareYieldVault {
    mapping(address => uint256) public deposits;
    uint256 public totalYieldAccrued;

    event Deposited(address indexed user, uint256 amount);
    event FeeHarvested(address indexed harvester, uint256 fee);

    constructor() payable {
        totalYieldAccrued = msg.value;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // VULNERABILITY: Arbitrary caller-specified basis points without cap allows draining protocol yield
    function harvestPerformanceFee(uint256 feeBps) external {
        // Flawed validation: allows feeBps > 10000 or unrestricted callers to drain
        require(feeBps <= 100000, "Invalid fee");
        uint256 feeAmount = (totalYieldAccrued * feeBps) / 10000;
        if (feeAmount > address(this).balance) {
            feeAmount = address(this).balance;
        }

        totalYieldAccrued -= feeAmount;
        payable(msg.sender).transfer(feeAmount);
        emit FeeHarvested(msg.sender, feeAmount);
    }

    receive() external payable {}
}
