// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecureERC4626Vault
 * @notice Synthetic control contract for ERC4626 Inflation benchmark.
 * Enforces virtual shares and assets offset (OpenZeppelin v5 pattern) to mitigate inflation donation attacks.
 */
contract SecureERC4626Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    uint256 private constant VIRTUAL_OFFSET = 1e3;

    function deposit() external payable returns (uint256 shares) {
        require(msg.value > 0, "Zero deposit");
        shares = (msg.value * (totalSupply + VIRTUAL_OFFSET)) / (totalAssets + 1);
        require(shares > 0, "Zero shares minted");

        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        totalAssets += msg.value;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");
        assets = (shares * (totalAssets + 1)) / (totalSupply + VIRTUAL_OFFSET);
        
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;
        payable(msg.sender).transfer(assets);
    }
}
