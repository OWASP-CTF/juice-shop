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

void describe('/rest/user/reset-password rate limiting', () => {
  void it('allows normal traffic but does not let callers reset their quota with X-Forwarded-For', async () => {
    const firstResponse = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'rate-limit@example.com',
        answer: 'irrelevant'
      })

    assert.equal(firstResponse.status, 401)
    assert.ok(firstResponse.text.includes('Password cannot be empty.'))

    for (let attempt = 2; attempt <= 100; attempt++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({
          'content-type': 'application/json',
          'X-Forwarded-For': `198.51.100.${attempt}`
        })
        .send({
          email: 'rate-limit@example.com',
          answer: 'irrelevant'
        })

      assert.equal(res.status, 401)
      assert.ok(res.text.includes('Password cannot be empty.'))
    }

    await request(app)
      .post('/rest/user/reset-password')
      .set({
        'content-type': 'application/json',
        'X-Forwarded-For': '203.0.113.101'
      })
      .send({
        email: 'rate-limit@example.com',
        answer: 'irrelevant'
      })
      .expect(429)
  })
})
