/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { readFileSync } from 'fs'
import { expect } from 'chai'
import path from 'path'

describe('web3 wallet contract', () => {
  const source = readFileSync(path.resolve('data/static/web3-snippets/ETHWalletBank.sol'), 'utf8')

  it('does not signal a successful exploit from the withdrawal path', () => {
    expect(source.match(/ContractExploited/g)).to.have.lengthOf(1)
  })

  it('updates the balance before transferring Ether', () => {
    const balanceUpdate = source.indexOf('balances[msg.sender] = balances[msg.sender].sub(_amount)')
    const transfer = source.indexOf('msg.sender.call{ value: _amount }')

    expect(balanceUpdate).to.be.greaterThan(-1)
    expect(transfer).to.be.greaterThan(balanceUpdate)
  })
})
