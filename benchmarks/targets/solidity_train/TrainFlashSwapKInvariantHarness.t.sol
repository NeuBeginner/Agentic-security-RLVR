// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainFlashSwapKInvariant} from "../src/TrainFlashSwapKInvariant.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainFlashSwapKInvariantHarness is Test {
    TrainFlashSwapKInvariant public amm;
    uint256 public constant INITIAL_ETH = 10 ether;
    uint256 public constant INITIAL_TOKEN = 10_000 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        amm = new TrainFlashSwapKInvariant{value: INITIAL_ETH}(INITIAL_TOKEN);
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(amm));
        exploit.runExploit();

        if (address(amm).balance < INITIAL_ETH) {
            emit SecurityInvariantBreached("AMM_FLASH_SWAP_K_INVARIANT_BYPASS", INITIAL_ETH - address(amm).balance);
            return;
        }
        revert("EXPLOIT_FAILED: AMM k-invariant preserved");
    }

    receive() external payable {}
}
