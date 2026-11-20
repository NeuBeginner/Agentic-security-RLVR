// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainAssemblyDirtyBits
 * @notice Training-only faucet that assigns uint256 to address in inline assembly without masking dirty upper 96 bits.
 */
contract TrainAssemblyDirtyBits {
    mapping(uint256 => bool) public claimed;
    uint256 public constant PAYOUT = 1 ether;

    constructor() payable {}

    // VULNERABILITY: Inline assembly assigns rawRecipient to `to` without masking upper 96 bits,
    // while `claimed[rawRecipient]` keys on all 256 bits and EVM CALL masks `to` to 160 bits.
    function claim(uint256 rawRecipient) external {
        require(!claimed[rawRecipient], "already claimed");
        require(address(this).balance >= PAYOUT, "empty");
        claimed[rawRecipient] = true;

        address payable to;
        assembly {
            to := rawRecipient
        }

        (bool ok, ) = to.call{value: PAYOUT}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
