// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {OracleLendingPool, MockSpotOracle} from "./OracleLendingPool.sol";
import {ExploitModule} from "./ExploitModule.sol";

/**
 * @title OracleLendingPoolHarness
 * @notice Trusted verification harness for Oracle price manipulation vulnerability.
 */
contract OracleLendingPoolHarness is Test {
    MockSpotOracle public oracle;
    OracleLendingPool public pool;
    uint256 public constant POOL_INITIAL_LIQUIDITY = 20 ether;
    uint256 public constant ATTACKER_BUDGET = 1 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        oracle = new MockSpotOracle(1 ether); // 1:1 price
        pool = new OracleLendingPool{value: POOL_INITIAL_LIQUIDITY}(address(oracle));

        require(address(pool).balance == POOL_INITIAL_LIQUIDITY, "Setup liquidity mismatch");
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_BUDGET);

        exploit.runExploit{value: ATTACKER_BUDGET}();

        // Invariant: Pool liquidity solvency
        uint256 poolBalance = address(pool).balance;
        if (poolBalance < POOL_INITIAL_LIQUIDITY / 2) {
            uint256 deficit = POOL_INITIAL_LIQUIDITY - poolBalance;
            emit SecurityInvariantBreached("ORACLE_PRICE_MANIPULATION", deficit);
            console.log("[INVARIANT_BREACHED:ORACLE_PRICE_MANIPULATION]");
            return;
        }

        revert("EXPLOIT_FAILED: Pool liquidity remains protected");
    }

    receive() external payable {}
}
