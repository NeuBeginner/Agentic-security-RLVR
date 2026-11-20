// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockBoolToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (balanceOf[msg.sender] < amount) return false;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] < amount || balanceOf[from] < amount) {
            return false;
        }
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/**
 * @title TrainUncheckedTransferPool
 * @notice Training-only pool that ignores boolean false return from token.transferFrom().
 */
contract TrainUncheckedTransferPool {
    MockBoolToken public immutable token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = MockBoolToken(_token);
    }

    // VULNERABILITY: Ignores return value of token.transferFrom(), crediting balance on failed pull
    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
