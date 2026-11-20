// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainUninitializedVault
 * @notice Training-only upgradeable-style vault with unprotected one-time initialize().
 */
contract TrainUninitializedVault {
    address public admin;
    bool public initialized;

    event Initialized(address indexed admin);
    event Drained(address indexed to, uint256 amount);

    constructor() payable {}

    // VULNERABILITY: Uninitialized admin allows any caller to invoke initialize() and take ownership
    function initialize(address _admin) external {
        require(!initialized, "already initialized");
        require(_admin != address(0), "zero admin");
        admin = _admin;
        initialized = true;
        emit Initialized(_admin);
    }

    function drain(address payable to) external {
        require(initialized && msg.sender == admin, "not admin");
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "drain failed");
        emit Drained(to, bal);
    }

    receive() external payable {}
}
