// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainMerkleDrop
 * @notice Training-only Merkle airdrop vulnerable to claim replay due to missing claimed mapping update.
 */
contract TrainMerkleDrop {
    bytes32 public immutable merkleRoot;

    address public lastAccount;
    uint256 public lastAmount;
    bytes32[] internal lastProof;

    event Claimed(address indexed account, uint256 amount);

    constructor(bytes32 _root) payable {
        merkleRoot = _root;
    }

    function getLastProof() external view returns (bytes32[] memory) {
        return lastProof;
    }

    // VULNERABILITY: Verifies Merkle proof but never records claimed[account] = true
    function claim(address payable account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 computed = keccak256(abi.encodePacked(account, amount));
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];
            if (computed <= sibling) {
                computed = keccak256(abi.encodePacked(computed, sibling));
            } else {
                computed = keccak256(abi.encodePacked(sibling, computed));
            }
        }
        require(computed == merkleRoot, "bad proof");
        require(address(this).balance >= amount, "empty");

        lastAccount = account;
        lastAmount = amount;
        delete lastProof;
        for (uint256 i = 0; i < proof.length; i++) {
            lastProof.push(proof[i]);
        }

        (bool ok, ) = account.call{value: amount}("");
        require(ok, "payout failed");
        emit Claimed(account, amount);
    }

    receive() external payable {}
}
