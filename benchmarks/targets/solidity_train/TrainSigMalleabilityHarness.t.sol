// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainSigMalleability} from "../src/TrainSigMalleability.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainSigMalleabilityHarness is Test {
    TrainSigMalleability public vault;
    uint256 internal authKey = 0xB0B;
    address public authority;
    address public alice = address(0xA11CE);
    uint256 public constant INITIAL_VAULT = 10 ether;
    uint256 public constant CLAIM_AMOUNT = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        authority = vm.addr(authKey);
        vault = new TrainSigMalleability{value: INITIAL_VAULT}(authority);

        bytes32 digest = keccak256(abi.encodePacked(alice, CLAIM_AMOUNT));
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authKey, ethDigest);
        vault.claim(alice, CLAIM_AMOUNT, v, r, s);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        exploit.runExploit();

        if (address(vault).balance < INITIAL_VAULT - CLAIM_AMOUNT) {
            emit SecurityInvariantBreached(
                "SIGNATURE_MALLEABILITY_REPLAY_DRAIN",
                (INITIAL_VAULT - CLAIM_AMOUNT) - address(vault).balance
            );
            return;
        }
        revert("EXPLOIT_FAILED: Malleable signature replay blocked");
    }

    receive() external payable {}
}
