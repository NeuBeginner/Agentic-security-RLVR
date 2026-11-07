// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SignatureReplayWallet
 * @notice Multisig-style execution wallet vulnerable to signature replay attacks.
 * Fails to record executed message hashes or track per-signer nonces.
 */
contract SignatureReplayWallet {
    address public signer;

    event Executed(address to, uint256 value, bytes data);

    constructor(address _signer) payable {
        signer = _signer;
    }

    // VULNERABILITY: Missing nonce or replay prevention tracking!
    // Same signature can be submitted repeatedly to drain contract funds.
    function executeWithSignature(
        address to,
        uint256 value,
        bytes calldata data,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(to, value, data));
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        address recovered = ecrecover(ethSignedMessageHash, v, r, s);
        require(recovered == signer, "Invalid signature");

        (bool success, ) = to.call{value: value}(data);
        require(success, "Execution failed");
        emit Executed(to, value, data);
    }

    receive() external payable {}
}
