// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainPushAuction
 * @notice Training-only auction vulnerable to push-payment DoS on leader refund.
 */
contract TrainPushAuction {
    address public currentLeader;
    uint256 public highestBid;

    event NewLeader(address indexed leader, uint256 amount);

    function placeBid() external payable {
        require(msg.value > highestBid, "bid too low");
        address prevLeader = currentLeader;
        uint256 prevBid = highestBid;

        currentLeader = msg.sender;
        highestBid = msg.value;

        // VULNERABILITY: Push-payment refund reverts entire bid if prevLeader rejects ETH
        if (prevLeader != address(0) && prevBid > 0) {
            (bool ok, ) = payable(prevLeader).call{value: prevBid}("");
            require(ok, "refund failed");
        }
        emit NewLeader(msg.sender, msg.value);
    }
}
