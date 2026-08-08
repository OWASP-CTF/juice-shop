/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Feedbacks', () => {
  void it('GET all feedback', async () => {
    const res = await request(app)
      .get('/api/Feedbacks')
    assert.equal(res.status, 200)
  })

  void it('POST sanitizes unsafe HTML from comment', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'I am a harm<script>steal-cookie</script><img src="csrf-attack"/><iframe src="evil-content"></iframe>less comment.',
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.comment, 'I am a harmless comment.')
  })

  void it('POST recursively sanitizes masked XSS without solving the challenge', async () => {
    challenges.persistedXssFeedbackChallenge.solved = false
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'Useful feedback. <<script>Foo</script>iframe src="javascript:alert(`xss`)">',
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.comment, 'Useful feedback. ')
    assert.equal(challenges.persistedXssFeedbackChallenge.solved, false)
  })

  void it('POST preserves plain text and allowed formatting in comments', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)

    const comment = 'Useful <strong>feedback</strong> with <em>emphasis</em>.'
    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment,
        rating: 5,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.comment, comment)
  })

  void it('POST anonymous feedback cannot forge another user ID', async () => {
    challenges.forgedFeedbackChallenge.solved = false
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'Lousy crap! You use sequelize 1.7.x? Welcome to SQL Injection-land, morons! As if that is not bad enough, you use z85/base85 and hashids for crypto? Even MD5 to hash passwords! Srsly?!?!',
        rating: 1,
        UserId: 3,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.UserId, null)
    assert.equal(challenges.forgedFeedbackChallenge.solved, false)
  })

  void it('POST feedback with a zero-star rating is rejected', async () => {
    challenges.zeroStarsChallenge.solved = false
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'Pickle Rick says your express-jwt 0.1.3 has Eurogium Edule and Hueteroneel in it!',
        rating: 0,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(challenges.zeroStarsChallenge.solved, false)
  })

  void it('POST feedback is associated with current user', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })

    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        comment: 'Stupid JWT secret and being typosquatted by epilogue-js and ngy-cookie!',
        rating: 5,
        UserId: 4,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.UserId, 4)
    assert.equal(challenges.forgedFeedbackChallenge.solved, false)
  })

  void it('POST feedback ignores a different passed user ID', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })

    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        comment: 'Bender\'s choice award!',
        rating: 5,
        UserId: 3,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.UserId, 4)
    assert.equal(challenges.forgedFeedbackChallenge.solved, false)
  })

  void it('POST feedback can be created without actually supplying comment', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.comment, null)
    assert.equal(res.body.data.rating, 1)
  })

  void it('POST feedback cannot be created without actually supplying rating', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.message, 'string')
    assert.ok(res.body.message.match(/notNull Violation: (Feedback\.)?rating cannot be null/))
  })

  void it('POST feedback cannot be created with wrong CAPTCHA answer', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: (captchaRes.body.answer + 1)
      })
    assert.equal(res.status, 401)
  })

  void it('POST feedback cannot be created with invalid CAPTCHA id', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        rating: 1,
        captchaId: 999999,
        captcha: 42
      })
    assert.equal(res.status, 401)
  })

  void it('POST consumes a CAPTCHA so it cannot be replayed', async () => {
    challenges.captchaBypassChallenge.solved = false
    const captchaRes = await request(app).get('/rest/captcha')
    const payload = {
      comment: 'One-time CAPTCHA regression',
      rating: 3,
      captchaId: captchaRes.body.captchaId,
      captcha: captchaRes.body.answer
    }

    const first = await request(app).post('/api/Feedbacks').set(jsonHeader).send(payload)
    const replay = await request(app).post('/api/Feedbacks').set(jsonHeader).send(payload)

    assert.equal(first.status, 201)
    assert.equal(replay.status, 401)
    assert.equal(challenges.captchaBypassChallenge.solved, false)
  })
})

void describe('/api/Feedbacks/:id', () => {
  void it('GET existing feedback by id is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Feedbacks/1')
    assert.equal(res.status, 401)
  })

  void it('GET existing feedback by id', async () => {
    const res = await request(app)
      .get('/api/Feedbacks/1')
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('PUT update existing feedback is forbidden via public API', async () => {
    const res = await request(app)
      .put('/api/Feedbacks/1')
      .set(jsonHeader)
      .send({
        comment: 'This sucks like nothing has ever sucked before',
        rating: 1
      })
    assert.equal(res.status, 401)
  })

  void it('PUT update existing feedback', async () => {
    const res = await request(app)
      .put('/api/Feedbacks/2')
      .set(authHeader)
      .send({
        rating: 0
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing feedback is forbidden via public API', async () => {
    const res = await request(app)
      .delete('/api/Feedbacks/1')
    assert.equal(res.status, 401)
  })

  void it('DELETE existing feedback', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const createRes = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'I will be gone soon!',
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(createRes.status, 201)
    assert.equal(typeof createRes.body.data.id, 'number')

    const res = await request(app)
      .delete('/api/Feedbacks/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(res.status, 200)
  })
})
