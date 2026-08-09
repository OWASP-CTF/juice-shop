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
  })

  void it('POST update username of authenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', 'Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('GET user profile never evaluates a `#{...}` username payload as code (CWE-95)', async () => {
    const postRes = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: '#{7*6}' })
      .redirects(0)
    assert.equal(postRes.status, 302)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    // If eval() were still in play, `#{7*6}` would have been evaluated to `42`.
    assert.ok(!res.text.includes('>42<'), 'username payload must not be evaluated')
    assert.ok(res.text.includes('#{7*6}'), 'unevaluated payload should be rendered as inert text')
  })

  void it('GET user profile does not execute arbitrary JS from a `#{...}` username payload (CWE-95)', async () => {
    const postRes = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: '#{global.__ssti_canary__ = true}' })
      .redirects(0)
    assert.equal(postRes.status, 302)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal((global as any).__ssti_canary__, undefined, 'eval() must never run for the username payload')
  })

  void it('GET user profile CSP header cannot be altered via profileImage injection (CWE-79)', async () => {
    // A non-resolvable host makes the server-side image fetch fail, so profileImage
    // falls back to storing the raw (attacker-controlled) URL string verbatim -
    // the same code path the "CSP Bypass" challenge relies on.
    await request(app)
      .post('/profile/image/url')
      .set('Cookie', authHeader.Cookie)
      .field('imageUrl', "https://notanimage.here/x; script-src 'unsafe-inline' 'self' 'unsafe-eval'")
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    const csp = res.headers['content-security-policy']
    assert.ok(csp, 'CSP header should be present')
    assert.ok(!csp.includes("'unsafe-inline'"), `attacker-controlled profileImage must not inject CSP keywords, got: ${csp}`)
    assert.equal(csp.split(';').length, 2, `profileImage must not add extra CSP directives, got: ${csp}`)
  })
})

async function isChallengeSolved (key: string): Promise<boolean> {
  const res = await request(app).get('/api/Challenges')
  const challenge = res.body.data.find((c: { key: string }) => c.key === key)
  assert.ok(challenge, `challenge with key '${key}' should exist`)
  return challenge.solved
}

void describe('SSTi / CSP Bypass exploit chain no longer solves the challenges', () => {
  void it('replaying the known exploit sequence leaves "sstiChallenge" and "usernameXssChallenge" unsolved', async () => {
    assert.equal(await isChallengeSolved('sstiChallenge'), false, 'precondition: sstiChallenge should start unsolved')
    assert.equal(await isChallengeSolved('usernameXssChallenge'), false, 'precondition: usernameXssChallenge should start unsolved')

    // Former SSTi exploit: a `#{...}` username payload used to be eval()-ed server-side.
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: "#{global.process.mainModule.require('child_process').exec('true')}" })
      .redirects(0)
    await request(app).get('/profile').set(authHeader)
    await request(app).get('/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3')

    assert.equal(await isChallengeSolved('sstiChallenge'), false, 'SSTi eval() gadget must be gone')

    // Former CSP Bypass exploit: disarm CSP via profileImage, then reflect a <script> tag via username.
    await request(app)
      .post('/profile/image/url')
      .set('Cookie', authHeader.Cookie)
      .field('imageUrl', "https://notanimage.here/a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'")
      .redirects(0)
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: '<script>alert(`xss`)</script>' })
      .redirects(0)
    await request(app).get('/profile').set(authHeader)

    assert.equal(await isChallengeSolved('usernameXssChallenge'), false, 'CSP injection via profileImage must be neutralized')
  })
})
