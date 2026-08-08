/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/b2b/v2/orders', () => {
  for (const payload of [
    '(function dos() { while(true); })()',
    '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")',
    'this.constructor.constructor("return process")().exit()'
  ]) {
    void it(`POST rejects executable "orderLinesData" without solving either RCE challenge: ${payload}`, async () => {
      challenges.rceChallenge.solved = false
      challenges.rceOccupyChallenge.solved = false

      const res = await request(app)
        .post('/b2b/v2/orders')
        .set(authHeader)
        .send({ orderLinesData: payload })

      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'orderLinesData must contain a valid JSON object or array')
      assert.equal(challenges.rceChallenge.solved, false)
      assert.equal(challenges.rceOccupyChallenge.solved, false)
    })
  }

  void it('POST accepts documented order line JSON without solving either RCE challenge', async () => {
    challenges.rceChallenge.solved = false
    challenges.rceOccupyChallenge.solved = false

    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        cid: 'test',
        orderLinesData: '[{"productId":12,"quantity":10000,"customerReference":["PO0000001.2","SM20180105|042"],"couponCode":"pes[Bh.u*t"}]'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.cid, 'test')
    assert.equal(challenges.rceChallenge.solved, false)
    assert.equal(challenges.rceOccupyChallenge.solved, false)
  })

  void it('POST new B2B order is forbidden without authorization token', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .send({})

    assert.equal(res.status, 401)
  })

  void it('POST new B2B order accepts arbitrary valid JSON', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        foo: 'bar',
        test: 42
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    if (res.body.cid !== undefined) assert.equal(typeof res.body.cid, 'string')
    assert.equal(typeof res.body.orderNo, 'string')
    assert.equal(typeof res.body.paymentDue, 'string')
  })

  void it('POST new B2B order has passed "cid" in response', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        cid: 'test'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.cid, 'test')
  })
})
