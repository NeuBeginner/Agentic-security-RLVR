// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainPushAuction} from "../src/TrainPushAuction.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainPushAuctionHarness is Test {
    TrainPushAuction public auction;
    address public honestBidder = address(0xCAFE);
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        auction = new TrainPushAuction();
        vm.deal(honestBidder, 5 ether);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(auction));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        vm.prank(honestBidder);
        try auction.placeBid{value: 2 ether}() {
            revert("EXPLOIT_FAILED: Auction remains live for subsequent bidders");
        } catch {
            emit SecurityInvariantBreached("PUSH_PAYMENT_DOS_LIVENESS", 1);
            return;
        }
    }

    receive() external payable {}
}
