/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { MemoryModel } from '../../models/memory'
import { UserModel } from '../../models/user'
import { getMemories } from '../../routes/memory'

const expect = chai.expect
chai.use(sinonChai)

describe('memory listing', () => {
  it('excludes authentication secrets from the joined user record', async () => {
    const findAll = sinon.stub(MemoryModel, 'findAll').resolves([])
    const res = { status: sinon.stub().returnsThis(), json: sinon.spy() } as any
    const next = sinon.spy()

    try {
      await getMemories()({} as any, res, next)

      expect(findAll).to.have.been.calledWith({
        include: [{ model: UserModel, attributes: { exclude: ['password', 'totpSecret'] } }]
      })
      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith({ status: 'success', data: [] })
      expect(next.called).to.equal(false)
    } finally {
      findAll.restore()
    }
  })
})
