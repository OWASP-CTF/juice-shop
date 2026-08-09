/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { checkKeys } from '../../routes/checkKeys'

const expect = chai.expect
chai.use(sinonChai)

describe('checkKeys', () => {
  it('rejects the private key derived from the previously exposed seed phrase', async () => {
    const req = {
      body: {
        privateKey: '0x5bcc3e9d38baa06e7bfaab80ae5957bbe8ef059e640311d7d6d465e6bc948e3e'
      }
    } as any
    const res = {
      status: sinon.stub().returnsThis(),
      json: sinon.spy()
    } as any

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.json).to.have.been.calledWith(sinon.match({ success: false }))
  })
})
