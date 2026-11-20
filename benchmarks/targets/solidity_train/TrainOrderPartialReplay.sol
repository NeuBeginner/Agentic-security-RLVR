// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainOrderPartialReplay
 * @notice Training-only signed order book that checks fillAmount <= maxAmount instead of cumulative filled.
 */
contract TrainOrderPartialReplay {
    struct Order {
        address maker;
        uint256 maxAmount;
        uint256 nonce;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    mapping(bytes32 => uint256) public filled;
    Order public lastOrder;

    constructor() payable {}

    function getLastOrder() external view returns (Order memory) {
        return lastOrder;
    }

    // VULNERABILITY: Checks fillAmount <= order.maxAmount instead of filled[orderHash] + fillAmount <= order.maxAmount
    function fillOrder(Order calldata order, uint256 fillAmount, address payable taker) external {
        require(fillAmount > 0 && fillAmount <= order.maxAmount, "exceeds max");
        bytes32 orderHash = keccak256(abi.encodePacked(order.maker, order.maxAmount, order.nonce));
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", orderHash));
        address recovered = ecrecover(ethDigest, order.v, order.r, order.s);
        require(recovered == order.maker && recovered != address(0), "bad sig");
        require(address(this).balance >= fillAmount, "empty");

        filled[orderHash] += fillAmount;
        lastOrder = order;

        (bool ok, ) = taker.call{value: fillAmount}("");
        require(ok, "fill failed");
    }

    receive() external payable {}
}
