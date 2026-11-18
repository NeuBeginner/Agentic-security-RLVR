// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainVoucherEscrow} from "../src/TrainVoucherEscrow.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainVoucherEscrowHarness is Test {
    TrainVoucherEscrow public escrow;
    uint256 internal authKey = 0xB0B;
    address public authority;
    address public alice = address(0xA11CE);
    uint256 public constant INITIAL_ESCROW = 10 ether;
    uint256 public constant VOUCHER_AMOUNT = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        authority = vm.addr(authKey);
        escrow = new TrainVoucherEscrow{value: INITIAL_ESCROW}(authority);

        bytes32 digest = keccak256(abi.encodePacked(alice, VOUCHER_AMOUNT));
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authKey, ethDigest);
        escrow.redeemVoucher(alice, VOUCHER_AMOUNT, v, r, s);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(escrow));
        exploit.runExploit();

        if (address(escrow).balance < INITIAL_ESCROW - VOUCHER_AMOUNT) {
            uint256 deficit = (INITIAL_ESCROW - VOUCHER_AMOUNT) - address(escrow).balance;
            emit SecurityInvariantBreached("SIGNATURE_REPLAY_DRAIN", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Voucher replay blocked");
    }

    receive() external payable {}
}
