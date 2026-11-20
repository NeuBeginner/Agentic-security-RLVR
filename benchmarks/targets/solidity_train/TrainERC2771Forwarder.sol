// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TrainProtectedTreasury {
    address public immutable trustedForwarder;
    address public immutable admin;

    constructor(address _forwarder, address _admin) payable {
        trustedForwarder = _forwarder;
        admin = _admin;
    }

    function _msgSender() internal view returns (address sender) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

    function sweep(address payable to) external {
        require(_msgSender() == admin, "not admin");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}

/**
 * @title TrainERC2771Forwarder
 * @notice Training-only forwarder that relays arbitrary calldata without appending msg.sender.
 */
contract TrainERC2771Forwarder {
    TrainProtectedTreasury public treasury;

    function setTreasury(address payable _treasury) external {
        require(address(treasury) == address(0), "already set");
        treasury = TrainProtectedTreasury(_treasury);
    }

    // VULNERABILITY: Forwards raw calldata without appending msg.sender, allowing caller to spoof trailing 20-byte address
    function relay(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "relay failed");
        return ret;
    }
}
