// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrainReadOnlyReentrancy
 * @notice Training-only LP + lending pool vulnerable to read-only reentrancy during removeLiquidity.
 */
contract TrainReadOnlyReentrancy {
    bool private locked;
    uint256 public poolEth;
    uint256 public totalLpSupply;
    uint256 public lendingReserve;

    mapping(address => uint256) public lpShares;
    mapping(address => uint256) public lpCollateral;
    mapping(address => uint256) public borrowed;

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    function fundLendingReserve() external payable {
        lendingReserve += msg.value;
    }

    function addLiquidity() external payable {
        require(msg.value > 0, "zero");
        lpShares[msg.sender] += msg.value;
        totalLpSupply += msg.value;
        poolEth += msg.value;
    }

    function depositLpCollateral() external payable {
        require(msg.value > 0, "zero");
        lpCollateral[msg.sender] += msg.value;
        totalLpSupply += msg.value;
        poolEth += msg.value;
    }

    function getSharePrice() public view returns (uint256) {
        if (totalLpSupply == 0) return 1e18;
        return (poolEth * 1e18) / totalLpSupply;
    }

    // VULNERABILITY: totalLpSupply is decremented before external ETH transfer, inflating getSharePrice() during callback
    function removeLiquidity(uint256 shares) external nonReentrant {
        require(lpShares[msg.sender] >= shares && shares > 0, "bad shares");
        uint256 ethOut = (shares * poolEth) / totalLpSupply;
        lpShares[msg.sender] -= shares;
        totalLpSupply -= shares;

        (bool ok, ) = msg.sender.call{value: ethOut}("");
        require(ok, "ethOut failed");
        poolEth -= ethOut;
    }

    // Missing nonReentrant: reads inflated getSharePrice() during removeLiquidity callback
    function borrowWithLpCollateral(uint256 amount) external {
        uint256 collateralValue = (lpCollateral[msg.sender] * getSharePrice()) / 1e18;
        require(borrowed[msg.sender] + amount <= collateralValue, "undercollateralized");
        require(lendingReserve >= amount, "empty reserve");
        borrowed[msg.sender] += amount;
        lendingReserve -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "borrow failed");
    }
}
