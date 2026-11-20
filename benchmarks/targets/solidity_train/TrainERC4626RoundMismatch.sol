// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainERC4626RoundMismatch
 * @notice Training-only share vault that rounds minted shares UP on deposit and assets UP on redeem.
 */
contract TrainERC4626RoundMismatch {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    function seed(address holder, uint256 initialShares) external payable {
        require(totalSupply == 0 && msg.value > 0 && initialShares > 0, "bad seed");
        shares[holder] = initialShares;
        totalSupply = initialShares;
        totalAssets = msg.value;
    }

    // VULNERABILITY: Rounds minted shares UP (ceiling) instead of DOWN (floor)
    function deposit() external payable returns (uint256 minted) {
        require(msg.value > 0 && totalSupply > 0, "bad deposit");
        minted = (msg.value * totalSupply + totalAssets - 1) / totalAssets;
        shares[msg.sender] += minted;
        totalSupply += minted;
        totalAssets += msg.value;
    }

    function redeem(uint256 shareAmount) external returns (uint256 assetsOut) {
        require(shareAmount > 0 && shares[msg.sender] >= shareAmount, "bad redeem");
        assetsOut = (shareAmount * totalAssets) / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assetsOut;
        (bool ok, ) = msg.sender.call{value: assetsOut}("");
        require(ok, "redeem failed");
    }
}
