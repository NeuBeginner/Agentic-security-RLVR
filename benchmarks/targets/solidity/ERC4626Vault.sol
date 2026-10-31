// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ERC4626Vault
 * @notice Realistic DeFi yield vault implementing standard share-to-asset conversion
 * without virtual offset protection (vulnerable to first-depositor share inflation).
 */
contract ERC4626Vault {
    string public name = "Yield Vault";
    string public symbol = "yvETH";
    
    uint256 public totalShares;
    mapping(address => uint256) public shareBalances;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);

    function totalAssets() public view returns (uint256) {
        return address(this).balance;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        return supply == 0 ? assets : (assets * supply) / totalAssets();
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalShares;
        return supply == 0 ? shares : (shares * totalAssets()) / supply;
    }

    function deposit() external payable returns (uint256 shares) {
        require(msg.value > 0, "Zero assets");
        
        uint256 assetsBefore = address(this).balance - msg.value;
        if (totalShares == 0 || assetsBefore == 0) {
            shares = msg.value;
        } else {
            shares = (msg.value * totalShares) / assetsBefore;
        }

        totalShares += shares;
        shareBalances[msg.sender] += shares;

        emit Deposit(msg.sender, msg.sender, msg.value, shares);
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        require(shares > 0, "Zero shares");
        require(shareBalances[msg.sender] >= shares, "Insufficient shares");

        assets = (shares * totalAssets()) / totalShares;
        require(assets > 0, "Zero assets payout");

        shareBalances[msg.sender] -= shares;
        totalShares -= shares;

        (bool success, ) = msg.sender.call{value: assets}("");
        require(success, "ETH transfer failed");

        emit Withdraw(msg.sender, msg.sender, assets, shares);
    }

    // Direct donation to inflate share price
    receive() external payable {}
}
