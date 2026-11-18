// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainFeeRoundingVault
 * @notice Training-only vault with fee rounding down to 0 and uncapped bonus minting.
 */
contract TrainFeeRoundingVault {
    mapping(address => uint256) public credits;
    uint256 public constant FEE_BPS = 50; // 0.5%

    constructor() payable {}

    function depositWithFee() external payable {
        require(msg.value > 0, "zero");
        // VULNERABILITY: For msg.value < 200 wei, fee rounds to 0, and bonus rounds up
        uint256 fee = (msg.value * FEE_BPS) / 10000;
        uint256 net = msg.value - fee;
        // Flawed loyalty bonus: +1 wei per call regardless of deposit size
        credits[msg.sender] += net + 1;
    }

    function withdrawCredits(uint256 amount) external {
        require(credits[msg.sender] >= amount, "insufficient credits");
        credits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
    }

    receive() external payable {}
}
