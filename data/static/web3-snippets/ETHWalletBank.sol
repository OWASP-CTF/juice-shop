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

  bool private locked;

  modifier nonReentrant() {
    require(!locked, "Reentrant call");
    locked = true;
    _;
    locked = false;
  }

  function withdraw(uint _amount) public nonReentrant {
    require(_amount <= 0.1 ether, "Withdrawal amount must be less than or equal to 0.1 ether");
    require(balances[msg.sender] >= _amount, "Insufficient balance");

    // Checks-effects-interactions: the balance is debited before any external
    // call, so a malicious fallback that calls back into withdraw() can no
    // longer drain the bank by spending the same balance repeatedly.
    balances[msg.sender] = balances[msg.sender].sub(_amount);

    (bool result, ) = msg.sender.call{ value: _amount }("");
    require(result, "Withdrawal call failed");
  }

  receive() external payable {}
}
// vuln-code-snippet end web3WalletChallenge
