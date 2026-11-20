// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainSwapAndPopQueue
 * @notice Training-only queue that leaves stale indexOf and deposits after swap-and-pop leave().
 */
contract TrainSwapAndPopQueue {
    address[] public queue;
    mapping(address => uint256) public indexOf;
    mapping(address => uint256) public deposits;

    function join() external payable {
        require(msg.value > 0, "zero");
        indexOf[msg.sender] = queue.length;
        queue.push(msg.sender);
        deposits[msg.sender] += msg.value;
    }

    // VULNERABILITY: Does not clear indexOf[msg.sender] or deposits[msg.sender], and does not update indexOf[last]
    function leave() external {
        uint256 idx = indexOf[msg.sender];
        require(idx < queue.length, "not in queue");

        address last = queue[queue.length - 1];
        queue[idx] = last;
        queue.pop();

        uint256 payout = deposits[msg.sender];
        require(address(this).balance >= payout, "insufficient");
        (bool ok, ) = msg.sender.call{value: payout}("");
        require(ok, "leave failed");
    }
}
