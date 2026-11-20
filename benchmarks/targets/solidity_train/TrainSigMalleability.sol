// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainSigMalleability
 * @notice Training-only ECDSA payout vault vulnerable to signature malleability (s-flipping).
 */
contract TrainSigMalleability {
    address public authority;
    mapping(bytes32 => bool) public usedSignatures;

    struct LastClaim {
        address recipient;
        uint256 amount;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    LastClaim public lastClaim;

    event Claimed(address indexed recipient, uint256 amount);

    constructor(address _authority) payable {
        authority = _authority;
    }

    // VULNERABILITY: Tracks signature tuple (v, r, s) without enforcing low-s (s <= secp256k1n / 2)
    function claim(
        address recipient,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 sigKey = keccak256(abi.encodePacked(v, r, s));
        require(!usedSignatures[sigKey], "sig already used");

        bytes32 digest = keccak256(abi.encodePacked(recipient, amount));
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        address recovered = ecrecover(ethDigest, v, r, s);
        require(recovered == authority && recovered != address(0), "bad sig");
        require(address(this).balance >= amount, "empty");

        usedSignatures[sigKey] = true;
        lastClaim = LastClaim(recipient, amount, v, r, s);

        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "payout failed");
        emit Claimed(recipient, amount);
    }

    receive() external payable {}
}
