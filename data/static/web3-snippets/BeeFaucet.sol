// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


interface Token {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract BeeFaucet {
    Token public token = Token(0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13);
    uint256 public balance = 200;

    /* The balance is checked before it is spent, not afterwards. Comparing an unsigned balance
       against zero is always true, so the old check could never reject anything, and holding the
       balance in a uint8 meant a large withdrawal wrapped the counter around instead of failing. */
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
