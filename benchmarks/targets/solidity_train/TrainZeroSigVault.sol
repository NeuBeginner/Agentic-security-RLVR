// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainZeroSigVault
 * @notice Training-only signature-gated vault that fails to reject ecrecover == address(0).
 */
contract TrainZeroSigVault {
    address public signer;
    mapping(bytes32 => bool) public used;

    event Claimed(address indexed to, uint256 amount);

    constructor(address _signer) payable {
        require(_signer != address(0), "zero signer");
        signer = _signer;
    }

    // VULNERABILITY: Missing else-revert when ecrecover returns address(0) on invalid signature
    function claim(
        address payable to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amount, nonce));
        require(!used[digest], "already used");
        used[digest] = true;

        address recovered = ecrecover(digest, v, r, s);
        if (recovered != address(0)) {
            require(recovered == signer, "bad sig");
        }

        require(address(this).balance >= amount, "empty");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
        emit Claimed(to, amount);
    }

    receive() external payable {}
}
