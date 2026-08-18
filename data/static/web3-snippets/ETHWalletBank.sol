// SPDX-License-Identifier: MIT
// vuln-code-snippet start web3WalletChallenge
pragma solidity ^0.6.12;
import 'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v3.3/contracts/math/SafeMath.sol';

contract ETHWalletBank {
  using SafeMath for uint256;

  mapping(address => uint) public balances;
  mapping(address => uint) public userWithdrawing;

  event ContractExploited(address indexed culprit);

  function ethdeposit(address _to) public payable {
    balances[_to] = balances[_to].add(msg.value);
  }

  function balanceOf(address _who) public view returns (uint balance) {
    return balances[_who];
  }

  /* A plain `call` with value hands execution over to the receiving account, which is free to
     call straight back into this function before the first invocation has finished. Any state
     this function still intends to write is therefore stale for the duration of that call, so
     the accounting has to be finished up front rather than afterwards:

     - the withdrawal is marked as in flight and refused if one is already running for this
       account, so a re-entrant call is rejected outright instead of racing the first one, and
     - the balance is debited before the transfer, following checks-effects-interactions, so
       even a re-entrant path that got past the flag would be measured against the reduced
       balance and stopped by the `require` below.

     Debiting only after the transfer let the balance check above pass repeatedly against the
     untouched pre-withdrawal figure, which is what allowed more ether to leave the contract
     than was ever deposited. The debit is also routed through SafeMath so that an unexpected
     accounting error reverts rather than wrapping around to an enormous balance. */
  function withdraw(uint _amount) public {
    require(_amount <= 0.1 ether, "Withdrawal amount must be less than or equal to 0.1 ether");
    require(balances[msg.sender] >= _amount, "Insufficient balance");
    require(userWithdrawing[msg.sender] == 0, "Withdrawal already in progress");

    userWithdrawing[msg.sender] = 1;
    balances[msg.sender] = balances[msg.sender].sub(_amount); // vuln-code-snippet neutral-line web3WalletChallenge
    (bool result, ) = msg.sender.call{ value: _amount }(""); // vuln-code-snippet neutral-line web3WalletChallenge
    require(result, "Withdrawal call failed"); // vuln-code-snippet neutral-line web3WalletChallenge
    userWithdrawing[msg.sender] = 0;
  }

  receive() external payable {}
}
// vuln-code-snippet end web3WalletChallenge
