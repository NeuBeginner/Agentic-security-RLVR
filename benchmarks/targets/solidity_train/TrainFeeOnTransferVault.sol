// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockFeeToken {
    string public name = "FeeToken";
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public feeSink = address(0xFEE);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _transfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        allowance[from][msg.sender] = allowed - amount;
        return _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        uint256 fee = (amount * 10) / 100;
        uint256 net = amount - fee;
        balanceOf[from] -= amount;
        balanceOf[to] += net;
        balanceOf[feeSink] += fee;
        return true;
    }
}

/**
 * @title TrainFeeOnTransferVault
 * @notice Training-only vault that credits pre-fee deposit amounts for fee-on-transfer tokens.
 */
contract TrainFeeOnTransferVault {
    MockFeeToken public immutable token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = MockFeeToken(_token);
    }

    // VULNERABILITY: Credits requested amount instead of actual post-fee balance delta
    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        require(token.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
