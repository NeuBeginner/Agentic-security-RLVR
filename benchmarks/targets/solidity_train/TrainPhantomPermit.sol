// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockWethLike {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    // Fallback accepts unknown selectors (e.g. permit) without reverting, mimicking WETH9
    fallback() external payable {}
    receive() external payable {}
}

/**
 * @title TrainPhantomPermit
 * @notice Training-only vault trusting low-level permit() call on a token with a fallback().
 */
contract TrainPhantomPermit {
    MockWethLike public immutable token;
    address public victim;
    mapping(address => uint256) public balances;

    constructor(address payable _token, address _victim) {
        token = MockWethLike(_token);
        victim = _victim;
    }

    // VULNERABILITY: Low-level permit() succeeds silently on MockWethLike fallback, allowing pre-approved transferFrom
    function depositWithPermit(
        address owner,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        (bool ok, ) = address(token).call(
            abi.encodeWithSignature(
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                owner,
                address(this),
                amount,
                deadline,
                v,
                r,
                s
            )
        );
        require(ok, "permit failed");
        require(token.transferFrom(owner, address(this), amount), "transferFrom failed");
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
