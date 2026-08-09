// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


interface Token {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract BeeFaucet {
    Token public token = Token(0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13);
    // uint8 caps the faucet at 255 and makes every arithmetic step a near-overflow; the
    // balance is a token amount and belongs in the same width as the token uses.
    uint256 public balance = 200;

    // The balance was spent before it was checked, and the check itself could never fail:
    // an unsigned value is always >= 0, so the require was a tautology guarding nothing.
    // The amount is now validated against the balance first, and the transfer must report
    // success - Token.transfer returns a bool, and discarding it let a failed payout look
    // like a completed withdrawal.
    function withdraw(uint256 amount) public {
        require(amount > 0, "Withdrawal amount must be positive");
        require(amount <= balance, "Withdrew more than the account balance!");
        balance -= amount;
        require(token.transfer(msg.sender, amount * 1000000000000000000), "BEE transfer failed");
    }

    function getBalance() public view returns (uint256) {
        return balance;
    }
}
