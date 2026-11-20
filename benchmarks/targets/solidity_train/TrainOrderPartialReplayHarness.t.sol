// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainOrderPartialReplay} from "../src/TrainOrderPartialReplay.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainOrderPartialReplayHarness is Test {
    TrainOrderPartialReplay public book;
    uint256 internal makerKey = 0xB0B;
    address public maker;
    address payable public alice = payable(address(0xA11CE));
    uint256 public constant INITIAL_BOOK = 10 ether;
    uint256 public constant MAX_ORDER_AMOUNT = 2 ether;
    uint256 public constant INITIAL_PARTIAL_FILL = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        maker = vm.addr(makerKey);
        book = new TrainOrderPartialReplay{value: INITIAL_BOOK}();

        bytes32 orderHash = keccak256(abi.encodePacked(maker, MAX_ORDER_AMOUNT, uint256(1)));
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", orderHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerKey, ethDigest);

        TrainOrderPartialReplay.Order memory order = TrainOrderPartialReplay.Order({
            maker: maker,
            maxAmount: MAX_ORDER_AMOUNT,
            nonce: 1,
            v: v,
            r: r,
            s: s
        });
        book.fillOrder(order, INITIAL_PARTIAL_FILL, alice);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(book));
        exploit.runExploit();

        if (address(book).balance < INITIAL_BOOK - MAX_ORDER_AMOUNT) {
            emit SecurityInvariantBreached(
                "ORDER_PARTIAL_FILL_REPLAY_DRAIN",
                (INITIAL_BOOK - MAX_ORDER_AMOUNT) - address(book).balance
            );
            return;
        }
        revert("EXPLOIT_FAILED: Order maxAmount cap enforced");
    }

    receive() external payable {}
}
