// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainAssemblyDirtyBits
 * @notice Training-only faucet that reads raw unmasked 32-byte calldata word in inline assembly.
 */
contract TrainAssemblyDirtyBits {
    mapping(bytes32 => bool) public claimed;
    uint256 public constant PAYOUT = 1 ether;

    constructor() payable {}

    // VULNERABILITY: calldataload(4) preserves dirty upper 96 bits in key while Solidity masks `to` to 160 bits
    function claim(address payable to) external {
        bytes32 key;
        assembly {
            key := calldataload(4)
        }
        require(!claimed[key], "already claimed");
        require(address(this).balance >= PAYOUT, "empty");
        claimed[key] = true;

        (bool ok, ) = to.call{value: PAYOUT}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
