// SPDX-License-Identifier: MIT
// vuln-code-snippet start nftMintChallenge
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract HoneyPotNFT is ERC721, Ownable, ReentrancyGuard {
    using SafeMath for uint256;

    IERC20 public token = IERC20(0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13);
    uint256 public constant mintPrice = 1000 * (10**18);
    uint256 public totalSupply = 0; // vuln-code-snippet neutral-line nftMintChallenge

    string public constant fixedMetadataHash = "QmRad1vxT3soFMNx9j3bBmkABb4C86anY1f5XeonosHy3m";
    event NFTMinted(address indexed owner, uint256 tokenId);

    constructor() ERC721("The Enchanted Honey Pot", "EHP") {}

    /* _safeMint hands control to the receiving address before the supply counter has moved, so a
       contract that mints could call back into mintNFT while totalSupply still held its old
       value: the same token id was handed out again and the event announced a mint that the
       counter never accounted for. The supply is settled before control leaves this function, and
       re-entry is refused outright by the audited OpenZeppelin guard. The payment is required as
       well, because transferFrom reports failure by returning false as well as by reverting, and
       that result was discarded - an unpaid caller still reached the mint. */
    function mintNFT() external nonReentrant {
        require(
            token.transferFrom(msg.sender, address(this), mintPrice),
            "Mint payment was not transferred"
        );
        uint256 tokenId = totalSupply;
        totalSupply = totalSupply.add(1); // vuln-code-snippet neutral-line nftMintChallenge
        _safeMint(msg.sender, tokenId);
        emit NFTMinted(msg.sender, tokenId); // vuln-code-snippet vuln-line nftMintChallenge
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "Token does not exist.");
        return fixedMetadataHash;
    }
}
// vuln-code-snippet end nftMintChallenge
