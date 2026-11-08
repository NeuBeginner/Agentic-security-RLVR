// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SecureOraclePool, ITWAPOracle} from "./SecureOraclePool.sol";
import {ExploitModule} from "./ExploitModule.sol";

contract MockTWAPOracle is ITWAPOracle {
    uint256 public price = 1e18; // 1 ETH = $1
    function getTwapPrice() external view override returns (uint256) {
        return price;
    }
}

/**
 * @title SecureOraclePoolHarness
 * @notice Fixed trusted harness for SecureOraclePool control.
 * Verifies that TWAP oracle resists spot price flash loan manipulation.
 */
contract SecureOraclePoolHarness is Test {
    SecureOraclePool public pool;
    MockTWAPOracle public oracle;
    uint256 public constant INITIAL_POOL_LIQUIDITY = 100 ether;
    uint256 public constant ATTACKER_BUDGET = 10 ether;

    event SecurityInvariantBreached(string invariantType, uint256 insolvencyDeficit);

    function setUp() public {
        oracle = new MockTWAPOracle();
        pool = new SecureOraclePool{value: INITIAL_POOL_LIQUIDITY}(address(oracle));
    }

    function testExploit() public {
        ExploitModule exploit = new ExploitModule(address(pool));
        vm.deal(address(this), ATTACKER_BUDGET);

        try exploit.runExploit{value: ATTACKER_BUDGET}() {
        } catch {}

        uint256 finalBalance = address(pool).balance;
        if (finalBalance < INITIAL_POOL_LIQUIDITY - ATTACKER_BUDGET) {
            uint256 deficit = INITIAL_POOL_LIQUIDITY - finalBalance;
            emit SecurityInvariantBreached("ORACLE_MANIPULATION_DRAIN", deficit);
            console.log("[INVARIANT_BREACHED:ORACLE_MANIPULATION_DRAIN]");
            return;
        }

        revert("EXPLOIT_FAILED: Safe control held. TWAP prevented oracle manipulation.");
    }
}
