// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainTruncatedDividend
 * @notice Training-only dividend vault vulnerable to uint32 integer truncation in withdraw check.
 */
contract TrainTruncatedDividend {
    mapping(address => uint256) public credits;

    event Credited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() payable {}

    function deposit() external payable {
        require(msg.value > 0, "zero");
        credits[msg.sender] += msg.value;
        emit Credited(msg.sender, msg.value);
    }

    // VULNERABILITY: Narrowing cast uint32(amount) truncates upper bits before balance check
    function withdraw(uint256 amount) external {
        require(amount > 0, "zero");
        uint32 truncated = uint32(amount);
        require(truncated <= credits[msg.sender], "insufficient");
        credits[msg.sender] -= truncated;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    receive() external payable {}
}
