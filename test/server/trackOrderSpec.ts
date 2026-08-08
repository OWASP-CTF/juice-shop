/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import * as db from '../../data/mongodb'
import { trackOrder } from '../../routes/trackOrder'

const expect = chai.expect
chai.use(sinonChai)

describe('trackOrder', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { params: {} }
    res = {
      status: sinon.stub(),
      json: sinon.spy()
    }
    res.status.returns(res)
  })

  afterEach(() => {
    sinon.restore()
  })

  it('rejects an object-valued order identifier before querying', () => {
    const findOne = sinon.stub(db.ordersCollection, 'findOne')
    req.params.id = { $ne: null }

    trackOrder()(req, res)

    expect(findOne.called).to.equal(false)
    expect(res.status).to.have.been.calledWith(400)
    expect(res.json).to.have.been.calledWith({ error: 'Wrong Param' })
  })

  it('queries a valid identifier using exact equality', async () => {
    const orderId = '5267-f9cd5882f54c75a3'
    const order = { orderId, email: 'masked' }
    const findOne = sinon.stub(db.ordersCollection, 'findOne').resolves(order)
    req.params.id = orderId

    await trackOrder()(req, res)

    expect(findOne).to.have.been.calledOnceWithExactly({ orderId })
    expect(res.json).to.have.been.calledWith({ status: 'success', data: [order] })
  })
})
