// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainShareVault
 * @notice Training-only ERC4626-style share vault without virtual offset protection.
 */
contract TrainShareVault {
    uint256 public totalSupplyShares;
    mapping(address => uint256) public balanceOfShares;

    event Deposited(address indexed user, uint256 assets, uint256 shares);
    event Redeemed(address indexed user, uint256 assets, uint256 shares);

    function poolAssets() public view returns (uint256) {
        return address(this).balance;
    }

    function previewRedeem(uint256 shares) public view returns (uint256) {
        if (totalSupplyShares == 0) return shares;
        return (shares * poolAssets()) / totalSupplyShares;
    }

    function depositAssets() external payable returns (uint256 shares) {
        require(msg.value > 0, "zero deposit");
        uint256 assetsBefore = address(this).balance - msg.value;
        if (totalSupplyShares == 0 || assetsBefore == 0) {
            shares = msg.value;
        } else {
            shares = (msg.value * totalSupplyShares) / assetsBefore;
        }
        totalSupplyShares += shares;
        balanceOfShares[msg.sender] += shares;
        emit Deposited(msg.sender, msg.value, shares);
    }

    function redeemShares(uint256 shares) external returns (uint256 assets) {
        require(shares > 0 && balanceOfShares[msg.sender] >= shares, "bad shares");
        assets = (shares * poolAssets()) / totalSupplyShares;
        require(assets > 0, "zero payout");
        balanceOfShares[msg.sender] -= shares;
        totalSupplyShares -= shares;
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok, "eth transfer failed");
        emit Redeemed(msg.sender, assets, shares);
    }

    receive() external payable {}
}
