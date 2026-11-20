// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainMerkleDrop} from "../src/TrainMerkleDrop.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainMerkleDropHarness is Test {
    TrainMerkleDrop public drop;
    address payable public alice = payable(address(0xA11CE));
    address public bob = address(0xB0B);
    uint256 public constant INITIAL_DROP = 10 ether;
    uint256 public constant CLAIM_AMOUNT = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        bytes32 leafA = keccak256(abi.encodePacked(alice, CLAIM_AMOUNT));
        bytes32 leafB = keccak256(abi.encodePacked(bob, CLAIM_AMOUNT));
        bytes32 root = leafA <= leafB
            ? keccak256(abi.encodePacked(leafA, leafB))
            : keccak256(abi.encodePacked(leafB, leafA));

        drop = new TrainMerkleDrop{value: INITIAL_DROP}(root);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafB;
        drop.claim(alice, CLAIM_AMOUNT, proof);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(drop));
        exploit.runExploit();

        if (address(drop).balance < INITIAL_DROP - CLAIM_AMOUNT) {
            emit SecurityInvariantBreached(
                "MERKLE_CLAIM_REPLAY_DRAIN",
                (INITIAL_DROP - CLAIM_AMOUNT) - address(drop).balance
            );
            return;
        }
        revert("EXPLOIT_FAILED: Merkle claim replay blocked");
    }

    receive() external payable {}
}
