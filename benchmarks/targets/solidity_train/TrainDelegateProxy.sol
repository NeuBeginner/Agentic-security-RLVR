// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainLogicImpl
 * @notice Benign logic contract whose slot 0 collides with TrainDelegateProxy.owner.
 */
contract TrainLogicImpl {
    uint256 public storedValue;

    function setValue(uint256 newValue) external {
        storedValue = newValue;
    }
}

/**
 * @title TrainDelegateProxy
 * @notice Training-only proxy vulnerable to delegatecall storage slot collision.
 */
contract TrainDelegateProxy {
    address public owner;
    address public implementation;

    event Executed(bytes data);
    event Withdrawn(address indexed to, uint256 amount);

    constructor(address _impl) payable {
        owner = msg.sender;
        implementation = _impl;
    }

    // VULNERABILITY: Unprotected delegatecall allows overwriting slot 0 (owner)
    function execute(bytes calldata data) external {
        (bool ok, ) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
        emit Executed(data);
    }

    function withdrawAll(address payable to) external {
        require(msg.sender == owner, "not owner");
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "withdraw failed");
        emit Withdrawn(to, bal);
    }

    receive() external payable {}
}
