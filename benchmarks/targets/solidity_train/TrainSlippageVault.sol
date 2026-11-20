// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainSlippageVault
 * @notice Training-only constant-product ETH/Token swap vault that ignores minTokensOut.
 */
contract TrainSlippageVault {
    uint256 public ethReserve;
    uint256 public tokenReserve;
    mapping(address => uint256) public tokenBalances;

    event Swapped(address indexed trader, uint256 ethIn, uint256 tokensOut);

    constructor(uint256 initialTokenReserve) payable {
        require(msg.value > 0 && initialTokenReserve > 0, "zero init");
        ethReserve = msg.value;
        tokenReserve = initialTokenReserve;
    }

    // VULNERABILITY: minTokensOut parameter is accepted but never enforced
    function swapEthForTokens(uint256 minTokensOut) external payable returns (uint256 tokensOut) {
        require(msg.value > 0, "zero eth");
        tokensOut = (msg.value * tokenReserve) / (ethReserve + msg.value);
        ethReserve += msg.value;
        tokenReserve -= tokensOut;
        tokenBalances[msg.sender] += tokensOut;
        // Missing: require(tokensOut >= minTokensOut, "slippage exceeded");
        emit Swapped(msg.sender, msg.value, tokensOut);
    }
}
