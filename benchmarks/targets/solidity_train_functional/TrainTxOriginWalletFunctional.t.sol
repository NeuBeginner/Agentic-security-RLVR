// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainTxOriginWallet} from "../src/TrainTxOriginWallet.sol";

contract TrainTxOriginWalletFunctional is Test {
    TrainTxOriginWallet public wallet;
    address public owner = address(0xA11CE);
    address public attacker = address(0xBAD);
    address payable public dest = payable(address(0x1234));

    function setUp() public {
        vm.deal(owner, 12 ether);
        vm.prank(owner, owner);
        wallet = new TrainTxOriginWallet{value: 10 ether}();
    }

    function testOwnerCanTransferAndReceiveEth() public {
        vm.prank(owner, owner);
        wallet.transferTo(dest, 3 ether);

        assertEq(dest.balance, 3 ether, "dest balance mismatch");
        assertEq(address(wallet).balance, 7 ether, "wallet balance mismatch");
        assertEq(wallet.owner(), owner, "owner changed unexpectedly");

        vm.prank(owner);
        (bool ok, ) = address(wallet).call{value: 1 ether}("");
        assertTrue(ok, "receive failed");
        assertEq(address(wallet).balance, 8 ether, "wallet did not receive eth");
    }

    function testNonOwnerDirectCallReverts() public {
        vm.prank(attacker, attacker);
        vm.expectRevert();
        wallet.transferTo(payable(attacker), 1 ether);
        assertEq(address(wallet).balance, 10 ether, "wallet balance changed on revert");
    }
}
