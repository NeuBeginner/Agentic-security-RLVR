// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainCallbackPool
 * @notice Training-only pool vulnerable to arbitrary external call (self-call) in executeWithCallback.
 */
contract TrainCallbackPool {
    event EmergencyReleased(address indexed to, uint256 amount);

    constructor() payable {}

    // VULNERABILITY: Arbitrary target.call(data) allows caller to invoke self-privileged emergencyRelease
    function executeWithCallback(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "callback failed");
        return ret;
    }

    function emergencyRelease(address payable to) external {
        require(msg.sender == address(this), "only pool");
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "release failed");
        emit EmergencyReleased(to, bal);
    }

    receive() external payable {}
}
