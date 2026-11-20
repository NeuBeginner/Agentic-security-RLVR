// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainTimelockBypass
 * @notice Training-only timelock treasury that forgets to require eta[txId] != 0 before execution.
 */
contract TrainTimelockBypass {
    address public admin;
    uint256 public constant DELAY = 2 days;
    mapping(bytes32 => uint256) public eta;

    constructor() payable {
        admin = msg.sender;
    }

    function queue(address payable to, uint256 amount, bytes calldata data) external returns (bytes32 txId) {
        require(msg.sender == admin, "not admin");
        txId = keccak256(abi.encode(to, amount, data));
        eta[txId] = block.timestamp + DELAY;
    }

    // VULNERABILITY: Missing `require(eta[txId] != 0, "not queued")` allows immediate execution of unqueued txId
    function execute(address payable to, uint256 amount, bytes calldata data) external {
        bytes32 txId = keccak256(abi.encode(to, amount, data));
        require(block.timestamp >= eta[txId], "timelock not ready");
        require(address(this).balance >= amount, "empty");
        eta[txId] = 0;

        (bool ok, ) = to.call{value: amount}(data);
        require(ok, "exec failed");
    }

    receive() external payable {}
}
