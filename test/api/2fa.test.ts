/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import jwt from 'jsonwebtoken'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'

const jsonHeader = { 'content-type': 'application/json' }

let app: Express

function getStatus (token: string) {
  return request(app)
    .get('/rest/2fa/status')
    .set({
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    })
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Users TOTP secret', () => {
  void it('POST ignores a mass-assigned TOTP secret', async () => {
    const email = 'totp-mass-assignment@bar.com'
    const plaintextSecret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email, password: '123456', totpSecret: plaintextSecret })

    assert.equal(res.status, 201)
    const user = await UserModel.findOne({ where: { email } })
    assert.ok(user)
    assert.equal(user.totpSecret, '')
  })
})

void describe('/rest/2fa/verify', () => {
  void it('stores the seeded TOTP secret encrypted at rest', async () => {
    const user = await UserModel.findByPk(10)

    assert.ok(user)
    assert.notEqual(user.totpSecret, 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
    assert.match(user.totpSecret, /^v1:/)
  })

  void it('POST should return a valid authentication when a valid tmp token is passed', async () => {
    assert.equal(challenges.twoFactorAuthUnsafeSecretStorageChallenge.solved, false)

    const tmpTokenWurstbrot = security.authorize({
      userId: 10,
      type: 'password_valid_needs_second_factor_token'
    })

    const totpToken = generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: tmpTokenWurstbrot,
        totpToken
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(typeof res.body.authentication.umail, 'string')
    assert.equal(typeof res.body.authentication.bid, 'number')
    assert.equal(res.body.authentication.umail, `wurstbrot@${config.get<string>('application.domain')}`)

    const token = res.body.authentication.token
    const tokenPayload = security.decode(token)
    assert.equal(tokenPayload?.data?.totpSecret, undefined)
    assert.equal(security.authenticatedUsers.get(token)?.data?.totpSecret, undefined)

    const authenticationDetails = await request(app)
      .get('/rest/user/authentication-details')
      .set({ Authorization: `Bearer ${token}` })
    const user = authenticationDetails.body.data.find((user: { email: string }) => user.email === `wurstbrot@${config.get<string>('application.domain')}`)
    assert.ok(user)
    assert.equal(user.totpSecret, undefined)
    assert.equal(challenges.twoFactorAuthUnsafeSecretStorageChallenge.solved, false)
  })

  void it('POST should fail if a invalid totp token is used', async () => {
    const tmpTokenWurstbrot = security.authorize({
      userId: 10,
      type: 'password_valid_needs_second_factor_token'
    })

    const totpToken = generateSync({ secret: 'BI6KJAURX3LL5VQI2ZBFVLUWSBYBDX4H' })

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: tmpTokenWurstbrot,
        totpToken
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if a unsigned tmp token is used', async () => {
    const tmpTokenWurstbrot = jwt.sign({
      userId: 10,
      type: 'password_valid_needs_second_factor_token'
    }, 'this_surly_isnt_the_right_key')

    const totpToken = generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: tmpTokenWurstbrot,
        totpToken
      })

    assert.equal(res.status, 401)
  })
})

void describe('/rest/2fa/status', () => {
  void it('GET should indicate 2fa is setup for 2fa enabled users', async () => {
    const { token } = await login(app, {
      email: `wurstbrot@${config.get<string>('application.domain')}`,
      password: 'EinBelegtesBrotMitSchinkenSCHINKEN!',
      totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'
    })

    const res = await getStatus(token)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.setup, 'boolean')
    assert.equal(res.body.setup, true)
  })

  void it('GET should indicate 2fa is not setup for users with 2fa disabled', async () => {
    const { token } = await login(app, {
      email: `J12934@${config.get<string>('application.domain')}`,
      password: '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'
    })

    const res = await getStatus(token)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.setup, 'boolean')
    assert.equal(typeof res.body.secret, 'string')
    assert.equal(typeof res.body.email, 'string')
    assert.equal(typeof res.body.setupToken, 'string')
    assert.equal(res.body.setup, false)
    assert.equal(res.body.email, `J12934@${config.get<string>('application.domain')}`)
  })

  void it('GET should return 401 when not logged in', async () => {
    const res = await request(app).get('/rest/2fa/status')

    assert.equal(res.status, 401)
  })
})

void describe('/rest/2fa/setup', () => {
  void it('POST should be able to setup 2fa for accounts without 2fa enabled', async () => {
    const email = 'fooooo1@bar.com'
    const password = '123456'
    const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const setupRes = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password,
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret })
      })

    assert.equal(setupRes.status, 200)

    const user = await UserModel.findOne({ where: { email } })
    assert.ok(user)
    assert.notEqual(user.totpSecret, secret)
    assert.match(user.totpSecret, /^v1:/)

    const statusRes = await getStatus(token)

    assert.equal(statusRes.status, 200)
    assert.equal(typeof statusRes.body.setup, 'boolean')
    assert.equal(statusRes.body.setup, true)
  })

  void it('POST should fail if the password doesnt match', async () => {
    const email = 'fooooo2@bar.com'
    const password = '123456'
    const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const res = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password: password + ' this makes the password wrong',
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret })
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if the initial token is incorrect', async () => {
    const email = 'fooooo3@bar.com'
    const password = '123456'
    const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const res = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password,
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret: 'OJQOJNTB46VLWUO4TVKXIULU2WLPFQOJ' })
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if the token is of the wrong type', async () => {
    const email = 'fooooo4@bar.com'
    const password = '123456'
    const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const res = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password,
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret_foobar'
        }),
        initialToken: generateSync({ secret })
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if the account has already set up 2fa', async () => {
    const email = `wurstbrot@${config.get<string>('application.domain')}`
    const password = 'EinBelegtesBrotMitSchinkenSCHINKEN!'
    const totpSecret = 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'

    const { token } = await login(app, { email, password, totpSecret })

    const res = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password,
        setupToken: security.authorize({
          secret: totpSecret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret: totpSecret })
      })

    assert.equal(res.status, 401)
  })
})

void describe('/rest/2fa/disable', () => {
  void it('POST should be able to disable 2fa for account with 2fa enabled', async () => {
    const email = 'fooooodisable1@bar.com'
    const password = '123456'
    const totpSecret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password, totpSecret })
    const { token } = await login(app, { email, password, totpSecret })

    const statusRes1 = await getStatus(token)
    assert.equal(statusRes1.status, 200)
    assert.equal(statusRes1.body.setup, true)

    const disableRes = await request(app)
      .post('/rest/2fa/disable')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({ password })

    assert.equal(disableRes.status, 200)

    const statusRes2 = await getStatus(token)
    assert.equal(statusRes2.status, 200)
    assert.equal(statusRes2.body.setup, false)
  })

  void it('POST should not be possible to disable 2fa without the correct password', async () => {
    const email = 'fooooodisable2@bar.com'
    const password = '123456'
    const totpSecret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password, totpSecret })
    const { token } = await login(app, { email, password, totpSecret })

    const statusRes1 = await getStatus(token)
    assert.equal(statusRes1.status, 200)
    assert.equal(statusRes1.body.setup, true)

    const disableRes = await request(app)
      .post('/rest/2fa/disable')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({ password: password + ' this makes the password wrong' })

    assert.equal(disableRes.status, 401)

    const statusRes2 = await getStatus(token)
    assert.equal(statusRes2.status, 200)
    assert.equal(statusRes2.body.setup, true)
  })
})
