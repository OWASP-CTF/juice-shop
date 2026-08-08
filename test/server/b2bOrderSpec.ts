/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { b2bOrder } from '../../routes/b2bOrder'
const expect = chai.expect
chai.use(sinonChai)

describe('b2bOrder', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    req = { body: { } }
    res = { json: sinon.spy() }
    res.status = sinon.stub().returns(res)
    next = sinon.spy()
    save = () => ({
      then () { }
    })
    challenges.rceChallenge = { solved: false, save } as unknown as Challenge
    challenges.rceOccupyChallenge = { solved: false, save } as unknown as Challenge
  })

  it('accepts order line JSON in the format documented by Swagger', () => {
    req.body.orderLinesData = '[{"productId":12,"quantity":10000,"customerReference":["PO0000001.2","SM20180105|042"],"couponCode":"pes[Bh.u*t"}]'

    b2bOrder()(req, res, next)

    expect(res.json.calledOnce).to.equal(true)
    expect(next.called).to.equal(false)
    expect(challenges.rceChallenge.solved).to.equal(false)
    expect(challenges.rceOccupyChallenge.solved).to.equal(false)
  })

  it('accepts customer-specific JSON objects without executing them', () => {
    req.body.orderLinesData = '{"hello":"world","foo":42,"bar":[false,true]}'

    b2bOrder()(req, res, next)

    expect(res.json.calledOnce).to.equal(true)
    expect(next.called).to.equal(false)
    expect(challenges.rceChallenge.solved).to.equal(false)
    expect(challenges.rceOccupyChallenge.solved).to.equal(false)
  })

  for (const payload of [
    '(function dos() { while(true); })()',
    '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")',
    'this.constructor.constructor("return process")().exit()'
  ]) {
    it(`rejects executable input without solving either RCE challenge: ${payload}`, () => {
      req.body.orderLinesData = payload

      b2bOrder()(req, res, next)

      expect(res.status).to.have.been.calledOnceWith(400)
      expect(res.json).to.have.been.calledOnceWith({ error: 'orderLinesData must contain a valid JSON object or array' })
      expect(next.called).to.equal(false)
      expect(challenges.rceChallenge.solved).to.equal(false)
      expect(challenges.rceOccupyChallenge.solved).to.equal(false)
    })
  }

  it('rejects JSON scalar values without solving either RCE challenge', () => {
    req.body.orderLinesData = '42'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledOnceWith(400)
    expect(challenges.rceChallenge.solved).to.equal(false)
    expect(challenges.rceOccupyChallenge.solved).to.equal(false)
  })
})
