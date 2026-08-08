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

void describe('/api', () => {
  void it('GET error when query /api without actual resource', async () => {
    const res = await request(app)
      .get('/api')
    assert.equal(res.status, 500)
  })
})

void describe('/rest', () => {
  void it('GET generic error without information leakage for an unrecognized REST path', async () => {
    const res = await request(app)
      .get('/rest/unrecognized')
    assert.equal(res.status, 500)
    assert.deepEqual(res.body, { error: 'The request could not be processed.' })
    assert.equal(res.text.includes('Unexpected path: /rest/unrecognized'), false)
  })
})
