/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/SecurityAnswers', () => {
  void it('GET all security answers is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST new security answer is forbidden without authentication', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)
  })

  void it('POST new security answer ignores the UserId in the body and binds to the caller', async () => {
    const credentials = { email: 'answer.binding@te.st', password: 'v3ry-s3cret' }
    const userRes = await register(app, credentials)
    const { token } = await login(app, credentials)

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        UserId: 1, // attempts to plant an answer on the admin account
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, userRes.body.data.id)
    assert.notEqual(res.body.data.UserId, 1)
  })

  void it('POST new security answer for a user who already has one fails from unique constraint', async () => {
    const credentials = { email: 'answer.duplicate@te.st', password: 'v3ry-s3cret' }
    await register(app, credentials)
    const { token } = await login(app, credentials)
    const authenticatedHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }

    const firstRes = await request(app)
      .post('/api/SecurityAnswers')
      .set(authenticatedHeader)
      .send({ SecurityQuestionId: 1, answer: 'Horst' })

    assert.equal(firstRes.status, 201)

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(authenticatedHeader)
      .send({ SecurityQuestionId: 1, answer: 'Horst' })

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Validation error')
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST security answer for a newly registered user', async () => {
    const credentials = { email: 'new.user@te.st', password: 'v3ry-s3cret' }
    await register(app, credentials)
    const { token } = await login(app, credentials)

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('PUT update existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .put('/api/SecurityAnswers/1')
      .set(authHeader)
      .send({
        answer: 'Blurp'
      })

    assert.equal(res.status, 401)
  })

  void it('DELETE existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .delete('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })
})
