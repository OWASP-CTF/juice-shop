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
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'

let app: Express
let authHeader: { Cookie: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Cookie: `token=${token}` }
}, { timeout: 60000 })

void describe('/profile', () => {
  void it('GET user profile is forbidden for unauthenticated user', async () => {
    const res = await request(app)
      .get('/profile')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`<h1>${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET user profile of authenticated user', async () => {
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('id="email" type="email" name="email" value="jim@juice-sh.op"'))
    assert.ok(res.text.includes('class="img-rounded" src="assets/public/images/uploads/default.svg"'))
  })

  void it('POST update username of authenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', 'Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('renders stored SSTI and XSS payloads literally without weakening the CSP or solving challenges', async () => {
    const username = "#{7 * 7}<script>alert('xss')</script>"
    const profileImage = "https://images.example.test/avatar.png; script-src 'unsafe-inline'"
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    assert.ok(user)
    user.setDataValue('username', username)
    user.setDataValue('profileImage', profileImage)
    await user.save()
    challenges.usernameXssChallenge.solved = false
    challenges.sstiChallenge.solved = false

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], "img-src 'self' data: http: https:; script-src 'self'")
    assert.ok(res.text.includes("#{7 * 7}&lt;script&gt;alert('xss')&lt;/script&gt;"))
    assert.ok(!res.text.includes("<script>alert('xss')</script>"))
    assert.ok(!res.text.includes('>49<'))
    assert.ok(res.text.includes('src="https://images.example.test/avatar.png; script-src \'unsafe-inline\'"'))

    await request(app)
      .get('/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3')

    assert.equal(challenges.usernameXssChallenge.solved, false)
    assert.equal(challenges.sstiChallenge.solved, false)
  })
})
