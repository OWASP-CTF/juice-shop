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

    bool private minting;

    modifier nonReentrant() {
        require(!minting, "Reentrant call");
        minting = true;
        _;
        minting = false;
    }

    function mintNFT() external nonReentrant {
        // The return value of transferFrom must be checked: a token that
        // signals failure by returning false instead of reverting would
        // otherwise hand out a free mint. State is also updated before
        // _safeMint, whose receiver callback can re-enter this function.
        require(token.transferFrom(msg.sender, address(this), mintPrice), "Payment failed");
        uint256 tokenId = totalSupply;
        totalSupply = totalSupply.add(1);
        _safeMint(msg.sender, tokenId);
        emit NFTMinted(msg.sender, tokenId);
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "Token does not exist.");
        return fixedMetadataHash;
    }
}
// vuln-code-snippet end nftMintChallenge
