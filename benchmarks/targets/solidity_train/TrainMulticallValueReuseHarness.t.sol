// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainMulticallValueReuse} from "../src/TrainMulticallValueReuse.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainMulticallValueReuseHarness is Test {
    TrainMulticallValueReuse public vault;
    address public saver = address(0x5A7E);
    uint256 public constant SAVER_DEPOSIT = 10 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        vault = new TrainMulticallValueReuse();
        vm.deal(saver, SAVER_DEPOSIT);
        vm.prank(saver);
        vault.deposit{value: SAVER_DEPOSIT}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(vault));
        vm.deal(address(this), ATTACKER_BUDGET);
        exploit.runExploit{value: ATTACKER_BUDGET}();

        if (address(vault).balance < vault.balances(saver)) {
            emit SecurityInvariantBreached(
                "MULTICALL_DELEGATECALL_MSG_VALUE_DRAIN",
                vault.balances(saver) - address(vault).balance
            );
            return;
        }
        revert("EXPLOIT_FAILED: Multicall accounting remained solvent");
    }

    receive() external payable {}
}
