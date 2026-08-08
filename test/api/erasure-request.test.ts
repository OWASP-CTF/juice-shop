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
import { challenges, users } from '../../data/datacache'
import { PrivacyRequestModel } from '../../models/privacyRequests'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/dataerasure', () => {
  void it('GET erasure form for logged-in users includes their email and security question', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('bjoern@owasp.org'))
    assert.ok(res.text.includes('Name of your favorite pet?'))
  })

  void it('GET erasure form rendering fails for users without assigned security answer', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: No answer found!'))
  })

  void it('GET erasure form rendering fails on unauthenticated access', async () => {
    const res = await request(app)
      .get('/dataerasure/')

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('You need to be logged in'))
  })

  void it('POST erasure request does not actually delete the user', async () => {
    challenges.lfrChallenge.solved = false
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: 'bjoern@owasp.org', securityAnswer: 'Zaya' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    const privacyRequest = await PrivacyRequestModel.findOne({ where: { UserId: users.bjoernOwasp.id } })
    assert.ok(privacyRequest)
    assert.equal(privacyRequest.deletionRequested, true)
    assert.equal(challenges.lfrChallenge.solved, false)

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    assert.equal(loginRes.status, 200)
  })

  void it('POST erasure form  fails on unauthenticated access', async () => {
    const res = await request(app)
      .post('/dataerasure/')

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('You need to be logged in'))
  })

  void it('POST erasure request with empty layout parameter returns', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ layout: null, email: 'bjoern@owasp.org', securityAnswer: 'Zaya' })

    assert.equal(res.status, 200)
  })

  void it('POST cannot submit an erasure request for another user', async () => {
    challenges.lfrChallenge.solved = false
    const { token } = await login(app, { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })
    const countBefore = await PrivacyRequestModel.count({ where: { UserId: users.jim.id } })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({
        email: 'admin@' + config.get<string>('application.domain'),
        securityAnswer: 'Samuel'
      })

    assert.equal(res.status, 403)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: users.jim.id } }), countBefore)
    assert.equal(challenges.lfrChallenge.solved, false)
  })

  void it('POST rejects local file references without reading them or solving the challenge', async () => {
    challenges.lfrChallenge.solved = false
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })
    const countBefore = await PrivacyRequestModel.count({ where: { UserId: users.bjoernOwasp.id } })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({
        layout: '../package.json',
        email: 'bjoern@owasp.org',
        securityAnswer: 'Zaya'
      })

    assert.equal(res.status, 400)
    assert.equal(res.text.includes('juice-shop'), false)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: users.bjoernOwasp.id } }), countBefore)
    assert.equal(challenges.lfrChallenge.solved, false)
  })
})
