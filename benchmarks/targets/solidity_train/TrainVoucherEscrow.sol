// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainVoucherEscrow
 * @notice Training-only voucher escrow vulnerable to signature replay.
 */
contract TrainVoucherEscrow {
    address public authority;

    struct LastVoucher {
        address recipient;
        uint256 amount;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    LastVoucher public lastVoucher;

    event VoucherClaimed(address indexed recipient, uint256 amount);

    constructor(address _authority) payable {
        authority = _authority;
    }

    // VULNERABILITY: No nonce or used-signature mapping prevents replay
    function redeemVoucher(
        address recipient,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(recipient, amount));
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        address recovered = ecrecover(ethDigest, v, r, s);
        require(recovered == authority && recovered != address(0), "bad sig");
        require(address(this).balance >= amount, "empty escrow");

        lastVoucher = LastVoucher(recipient, amount, v, r, s);

        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "payout failed");
        emit VoucherClaimed(recipient, amount);
    }

    receive() external payable {}
}
