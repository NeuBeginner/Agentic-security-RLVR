// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainTxOriginWallet
 * @notice Training-only wallet vulnerable to tx.origin authorization bypass.
 */
contract TrainTxOriginWallet {
    address public owner;

    event Transferred(address indexed dest, uint256 amount);

    constructor() payable {
        owner = msg.sender;
    }

    // VULNERABILITY: Uses tx.origin instead of msg.sender for authorization
    function transferTo(address payable dest, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        require(address(this).balance >= amount, "insufficient");
        (bool ok, ) = dest.call{value: amount}("");
        require(ok, "send failed");
        emit Transferred(dest, amount);
    }

    receive() external payable {}
}
