// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainMulticallValueReuse
 * @notice Training-only vault with payable multicall(delegatecall) that reuses msg.value.
 */
contract TrainMulticallValueReuse {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: delegatecall in a loop preserves msg.value on every subcall
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "multicall failed");
            results[i] = ret;
        }
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
    }
}
