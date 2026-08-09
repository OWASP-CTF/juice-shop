/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
    assert.equal(res.status, 200)
  })

  // This used to assert the opposite - that a tautology injected into orderId returned every
  // order in the collection, complete with each customer's email address. The id is no longer
  // evaluated as a query expression, so it cannot, and the test now pins that down.
  void it('GET does not return all orders when injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].email, undefined)
  })

  void it('GET normalises an unmatched order id to the order-id alphabet before echoing it', async () => {
    const payload = '<iframe src="javascript:alert(`xss`)">'
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent(payload)}`)
    assert.equal(res.status, 200)
    assert.match(res.body.data[0].orderId, /^[\w-]*$/)
  })

  void it('GET still resolves a well-formed order id untouched', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cc73d6d92eba3e')
    assert.equal(res.status, 200)
    assert.equal(res.body.data[0].orderId, '5267-f9cc73d6d92eba3e')
  })

  void it('GET does not let a quote in the id break out of the order lookup', async () => {
    // A `$where`-interpolated id used to throw a SyntaxError straight out of the query engine,
    // answering with a 500 and a server stack trace instead of a result.
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent('\'"><svg onload=alert(1)>')}`)
    assert.equal(res.status, 200)
    assert.match(res.body.data[0].orderId, /^[\w-]*$/)
  })

  void it('does not mark the reflected-XSS challenge solved when the classic payload is submitted', async () => {
    await request(app)
      .get('/rest/track-order/%3Ciframe%20src%3D%22javascript%3Aalert(%60xss%60)%22%3E')
    const res = await request(app)
      .get('/api/Challenges')
    assert.equal(res.status, 200)
    const reflectedXss = res.body.data.find((c: { key: string }) => c.key === 'reflectedXssChallenge')
    assert.ok(reflectedXss, 'expected reflectedXssChallenge to be present in /api/Challenges')
    assert.equal(reflectedXss.solved, false)
  })
})
