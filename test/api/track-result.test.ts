/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let realOrderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, {
    email: 'admin@' + config.get<string>('application.domain'),
    password: 'admin123'
  })
  const historyRes = await request(app)
    .get('/rest/order-history')
    .set({ Authorization: `Bearer ${token}` })
  realOrderId = historyRes.body.data[0].orderId
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for a real order id returns that order', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${realOrderId}`)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, realOrderId)
    assert.equal(typeof res.body.data[0].email, 'string')
    assert.equal(typeof res.body.data[0].totalPrice, 'number')
    assert.ok(Array.isArray(res.body.data[0].products))
  })

  void it('GET tracking results for an unknown order id returns only a placeholder, not real order data', async () => {
    const res = await request(app)
      .get('/rest/track-order/does-not-exist')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(res.body.data[0], { orderId: 'does-not-exist' })
  })

  void it('GET all orders by injecting into orderId no longer leaks unrelated orders', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    // A successful $where injection used to return every order in the database.
    // The payload must now be treated as a literal (non-matching) orderId instead.
    assert.equal(res.body.data.length, 1)
    assert.notEqual(res.body.data[0].orderId, realOrderId)
    assert.equal(res.body.data[0].email, undefined)
    assert.equal(res.body.data[0].products, undefined)
  })
})
