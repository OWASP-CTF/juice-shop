// SPDX-License-Identifier: MIT
// vuln-code-snippet start nftMintChallenge
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract HoneyPotNFT is ERC721, Ownable {
    using SafeMath for uint256;

    IERC20 public token = IERC20(0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13);
    uint256 public constant mintPrice = 1000 * (10**18);
    uint256 public totalSupply = 0; // vuln-code-snippet neutral-line nftMintChallenge

    string public constant fixedMetadataHash = "QmRad1vxT3soFMNx9j3bBmkABb4C86anY1f5XeonosHy3m";
    event NFTMinted(address indexed owner, uint256 tokenId);

    constructor() ERC721("The Enchanted Honey Pot", "EHP") {}

    function mintNFT() external {
        /* transferFrom reports failure by returning false. Ignoring that return value meant the
           NFT was minted whether or not the BEE payment ever settled - the caller only had to make
           the transfer fail. The mint is the effect of a payment, so the payment is checked first
           and the mint only happens if it succeeded. */
        require(token.transferFrom(msg.sender, address(this), mintPrice), "BEE payment failed");
        uint256 tokenId = totalSupply;
        totalSupply = totalSupply.add(1);
        _safeMint(msg.sender, tokenId);
        /* The id is taken before the counter moves. Deriving it afterwards as an unchecked
           totalSupply - 1 wrapped to 2^256-1 on the very first mint. */
        emit NFTMinted(msg.sender, tokenId);
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "Token does not exist.");
        return fixedMetadataHash;
    }
}
// vuln-code-snippet end nftMintChallenge
