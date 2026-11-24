// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TrainSlippageVault} from "../src/TrainSlippageVault.sol";

contract TrainSlippageVaultFunctional is Test {
    TrainSlippageVault public vault;
    address public trader = address(0xA11CE);

    function setUp() public {
        vault = new TrainSlippageVault{value: 10 ether}(10_000 ether);
        vm.deal(trader, 5 ether);
    }

    function testNormalSwapAndSlippageGuard() public {
        uint256 ethIn = 1 ether;
        uint256 expectedOut = (ethIn * 10_000 ether) / (10 ether + ethIn);

        vm.prank(trader);
        uint256 tokensOut = vault.swapEthForTokens{value: ethIn}(expectedOut);

        assertEq(tokensOut, expectedOut, "amm output mismatch");
        assertEq(vault.tokenBalances(trader), expectedOut, "trader token balance mismatch");
        assertEq(vault.ethReserve(), 11 ether, "ethReserve mismatch");
        assertEq(vault.tokenReserve(), 10_000 ether - expectedOut, "tokenReserve mismatch");

        vm.prank(trader);
        vm.expectRevert();
        vault.swapEthForTokens{value: 1 ether}(10_000 ether);
    }
}
