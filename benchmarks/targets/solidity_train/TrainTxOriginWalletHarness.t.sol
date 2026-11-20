// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainTxOriginWallet} from "../src/TrainTxOriginWallet.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainTxOriginWalletHarness is Test {
    TrainTxOriginWallet public wallet;
    address public owner = address(0xA11CE);
    uint256 public constant INITIAL_BALANCE = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vm.deal(owner, INITIAL_BALANCE);
        vm.prank(owner, owner);
        wallet = new TrainTxOriginWallet{value: INITIAL_BALANCE}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(wallet));
        vm.prank(owner, owner);
        exploit.runExploit();

        if (address(wallet).balance < INITIAL_BALANCE) {
            emit SecurityInvariantBreached("TX_ORIGIN_AUTH_BYPASS", INITIAL_BALANCE - address(wallet).balance);
            return;
        }
        revert("EXPLOIT_FAILED: Wallet funds remained protected");
    }

    receive() external payable {}
}
