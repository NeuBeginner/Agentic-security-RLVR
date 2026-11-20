// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/**
 * @title TrainERC721CallbackLender
 * @notice Training-only NFT receipt lender vulnerable to onERC721Received reentrancy.
 */
contract TrainERC721CallbackLender {
    uint256 public totalMinted;
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public positionsMinted;
    mapping(address => uint256) public borrowLimit;
    mapping(address => uint256) public borrowed;

    constructor() payable {}

    // VULNERABILITY: External onERC721Received callback runs before positionsMinted[msg.sender] += 1
    function mintPosition() external returns (uint256 tokenId) {
        require(positionsMinted[msg.sender] < 1, "max 1 position");
        tokenId = ++totalMinted;
        ownerOf[tokenId] = msg.sender;
        borrowLimit[msg.sender] += 1 ether;

        if (msg.sender.code.length > 0) {
            bytes4 retval = IERC721Receiver(msg.sender).onERC721Received(msg.sender, address(0), tokenId, "");
            require(retval == IERC721Receiver.onERC721Received.selector, "bad receiver");
        }

        positionsMinted[msg.sender] += 1;
    }

    function borrow(uint256 amount) external {
        require(borrowed[msg.sender] + amount <= borrowLimit[msg.sender], "exceeds limit");
        require(address(this).balance >= amount, "empty pool");
        borrowed[msg.sender] += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "borrow failed");
    }

    receive() external payable {}
}
