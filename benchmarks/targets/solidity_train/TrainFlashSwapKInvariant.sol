// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFlashSwapCallee {
    function onFlashSwap(uint256 ethOut, bytes calldata data) external;
}

/**
 * @title TrainFlashSwapKInvariant
 * @notice Training-only AMM pool that checks k-invariant against stale storage reserves instead of live balance.
 */
contract TrainFlashSwapKInvariant {
    uint256 public reserve0;
    uint256 public reserve1;

    constructor(uint256 _reserve1) payable {
        require(msg.value > 0 && _reserve1 > 0, "zero init");
        reserve0 = msg.value;
        reserve1 = _reserve1;
    }

    // VULNERABILITY: Checks stale storage reserve0 * reserve1 instead of actual address(this).balance
    function flashSwap(uint256 ethOut, address receiver, bytes calldata data) external {
        require(ethOut > 0 && ethOut <= address(this).balance, "bad amount");
        uint256 kBefore = reserve0 * reserve1;

        (bool ok, ) = receiver.call{value: ethOut}("");
        require(ok, "ethOut failed");

        if (receiver.code.length > 0 && data.length > 0) {
            IFlashSwapCallee(receiver).onFlashSwap(ethOut, data);
        }

        require(reserve0 * reserve1 >= kBefore, "k invariant broken");
    }

    receive() external payable {}
}
