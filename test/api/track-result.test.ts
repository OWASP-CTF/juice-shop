/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import * as db from '../../data/mongodb'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for an exact valid order id', async () => {
    const orders = await db.ordersCollection.find()
    const order = orders[0]

    const res = await request(app)
      .get(`/rest/track-order/${order.orderId}`)

    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, order.orderId)
    assert.equal(challenges.noSqlOrdersChallenge.solved, false)
    assert.equal(challenges.reflectedXssChallenge.solved, false)
  })

  void it('rejects a NoSQL injection string without returning orders', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.deepEqual(res.body, { error: 'Wrong Param' })
    assert.equal(challenges.noSqlOrdersChallenge.solved, false)
    assert.equal(challenges.reflectedXssChallenge.solved, false)
  })

  void it('rejects a serialized query operator object', async () => {
    const res = await request(app)
      .get('/rest/track-order/%7B%22%24ne%22%3Anull%7D')

    assert.equal(res.status, 400)
    assert.deepEqual(res.body, { error: 'Wrong Param' })
    assert.equal(challenges.noSqlOrdersChallenge.solved, false)
    assert.equal(challenges.reflectedXssChallenge.solved, false)
  })

  void it('rejects the reflected XSS payload without echoing it', async () => {
    const payload = '<iframe src="javascript:alert(`xss`)">'
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent(payload)}`)

    assert.equal(res.status, 400)
    assert.equal(JSON.stringify(res.body).includes(payload), false)
    assert.equal(challenges.noSqlOrdersChallenge.solved, false)
    assert.equal(challenges.reflectedXssChallenge.solved, false)
  })
})
