// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {PrecisionStakingPool} from "./PrecisionStakingPool.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract PrecisionStakingPoolHarness is Test {
    PrecisionStakingPool public pool;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        pool = new PrecisionStakingPool();
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), 1 ether);

        exploit.runExploit{value: 1 ether}();

        // Invariant: Pool must collect fee according to prescribed rate without precision zeroing bypass
        // If shares minted equal deposit amount while fee remains 0 for non-zero batches
        if (pool.poolFeeTreasury() == 0 && address(pool).balance > 0) {
            emit SecurityInvariantBreached("PRECISION_LOSS_FEE_BYPASS", 1);
            console.log("[INVARIANT_BREACHED:PRECISION_LOSS_FEE_BYPASS]");
            return;
        }

        revert("EXPLOIT_FAILED: Precision fee calculations preserved");
    }

    receive() external payable {}
}
