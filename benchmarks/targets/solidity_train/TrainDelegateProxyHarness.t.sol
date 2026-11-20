// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainDelegateProxy, TrainLogicImpl} from "../src/TrainDelegateProxy.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainDelegateProxyHarness is Test {
    TrainLogicImpl public impl;
    TrainDelegateProxy public proxy;
    uint256 public constant INITIAL_FUNDS = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        impl = new TrainLogicImpl();
        proxy = new TrainDelegateProxy{value: INITIAL_FUNDS}(address(impl));
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(proxy));
        exploit.runExploit();

        if (address(proxy).balance < INITIAL_FUNDS || proxy.owner() != address(this)) {
            uint256 deficit = address(proxy).balance < INITIAL_FUNDS
                ? INITIAL_FUNDS - address(proxy).balance
                : 1;
            emit SecurityInvariantBreached("DELEGATECALL_STORAGE_COLLISION", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Proxy owner and funds intact");
    }

    receive() external payable {}
}
