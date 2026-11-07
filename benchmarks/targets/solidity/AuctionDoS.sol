// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AuctionDoS
 * @notice Vulnerable auction contract susceptible to Denial of Service (DoS) via push-over-pull.
 * Directly refunds previous highest bidder inside bid(); if previous bidder reverts in receive(),
 * the auction becomes permanently blocked.
 */
contract AuctionDoS {
    address public highestBidder;
    uint256 public highestBid;

    event HighestBidIncreased(address bidder, uint256 amount);

    // VULNERABILITY: DoS via external call push payment revert
    function bid() external payable {
        require(msg.value > highestBid, "Bid not high enough");

        if (highestBidder != address(0)) {
            // Push payment: if previous bidder contract has no receive() or reverts, whole tx reverts
            (bool success, ) = payable(highestBidder).call{value: highestBid}("");
            require(success, "Refund failed");
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
        emit HighestBidIncreased(msg.sender, msg.value);
    }
}
