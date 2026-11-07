// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SignatureReplayWallet} from "./SignatureReplayWallet.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract SignatureReplayWalletHarness is Test {
    SignatureReplayWallet public wallet;
    uint256 internal signerPrivateKey = 0xA11CE;
    address public signer;
    uint256 public constant WALLET_BALANCE = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        signer = vm.addr(signerPrivateKey);
        wallet = new SignatureReplayWallet{value: WALLET_BALANCE}(signer);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(wallet));
        
        // Single authorized withdrawal payload
        bytes32 messageHash = keccak256(abi.encodePacked(address(exploit), uint256(1 ether), bytes("")));
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, ethSignedMessageHash);

        // Attacker attempts replay
        exploit.runSignatureReplay(r, s, v);

        // Invariant: Balance should only drop by 1 ether, not multiple times
        if (address(wallet).balance < WALLET_BALANCE - 1 ether) {
            uint256 deficit = WALLET_BALANCE - address(wallet).balance;
            emit SecurityInvariantBreached("SIGNATURE_REPLAY_DRAIN", deficit);
            console.log("[INVARIANT_BREACHED:SIGNATURE_REPLAY_DRAIN]");
            return;
        }

        revert("EXPLOIT_FAILED: Signature replay prevented");
    }

    receive() external payable {}
}
