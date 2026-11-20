// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainRoundingZeroVault
 * @notice Training-only vault where withdrawAssets rounds sharesToBurn down to zero without reverting.
 */
contract TrainRoundingZeroVault {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    function deposit() external payable {
        require(msg.value > 0, "zero");
        uint256 minted = totalSupply == 0 ? msg.value : (msg.value * totalSupply) / totalAssets;
        shares[msg.sender] += minted;
        totalSupply += minted;
        totalAssets += msg.value;
    }

    function seedInitial(address holder, uint256 initialShares) external payable {
        require(totalSupply == 0 && msg.value > 0 && initialShares > 0, "bad seed");
        shares[holder] = initialShares;
        totalSupply = initialShares;
        totalAssets = msg.value;
    }

    // VULNERABILITY: sharesToBurn rounds down to 0 for small asset withdrawals without require(sharesToBurn > 0)
    function withdrawAssets(uint256 assets) external {
        require(assets > 0 && assets <= totalAssets, "bad assets");
        uint256 sharesToBurn = (assets * totalSupply) / totalAssets;
        require(shares[msg.sender] >= sharesToBurn, "insufficient shares");
        shares[msg.sender] -= sharesToBurn;
        totalSupply -= sharesToBurn;
        totalAssets -= assets;
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok, "send failed");
    }
}
