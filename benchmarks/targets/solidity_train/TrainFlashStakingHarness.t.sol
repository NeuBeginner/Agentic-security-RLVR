// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainFlashStaking} from "../src/TrainFlashStaking.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract TrainFlashStakingHarness is Test {
    TrainFlashStaking public staking;
    uint256 public constant REWARD_RESERVE = 8 ether;
    uint256 public constant FLASH_CAPITAL = 6 ether;

    event SecurityInvariantBreached(string invariantType, uint256 deficit);

    function setUp() public {
        staking = new TrainFlashStaking{value: REWARD_RESERVE}();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(staking));
        vm.deal(address(this), FLASH_CAPITAL);
        exploit.runExploit{value: FLASH_CAPITAL}();

        // Any single-tx bonus drain > 0.1 ether violates time-weighted staking invariant
        if (address(staking).balance < REWARD_RESERVE - 0.1 ether) {
            uint256 deficit = REWARD_RESERVE - address(staking).balance;
            emit SecurityInvariantBreached("FLASH_LOAN_REWARD_DISTORTION", deficit);
            return;
        }
        revert("EXPLOIT_FAILED: Flash staking bonus remained bounded");
    }

    receive() external payable {}
}
