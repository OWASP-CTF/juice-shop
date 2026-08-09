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

// Reference implementation used only to independently verify the answer
// computed server-side without eval(), respecting standard operator
// precedence (multiplication before addition/subtraction).
function referenceAnswer (expression: string): number {
  const match = /^(\d+)([*+-])(\d+)([*+-])(\d+)$/.exec(expression)
  assert.ok(match, `Unexpected CAPTCHA expression format: ${expression}`)
  const [, a, op1, b, op2, c] = match
  const terms = [Number(a), Number(b), Number(c)]
  const ops = [op1, op2]
  // resolve multiplication first
  for (let i = 0; i < ops.length; i++) {
    if (ops[i] === '*') {
      terms.splice(i, 2, terms[i] * terms[i + 1])
      ops.splice(i, 1)
      i--
    }
  }
  let result = terms[0]
  for (let i = 0; i < ops.length; i++) {
    result = ops[i] === '+' ? result + terms[i + 1] : result - terms[i + 1]
  }
  return result
}

void describe('/rest/captcha', () => {
  void it('GET returns a captcha whose answer is computed without eval() and matches standard operator precedence', async () => {
    // fetch a good number of captchas to exercise every operator combination
    for (let i = 0; i < 30; i++) {
      const res = await request(app)
        .get('/rest/captcha')
      assert.equal(res.status, 200)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.match(res.body.captcha, /^\d+[*+-]\d+[*+-]\d+$/)
      assert.equal(res.body.answer, referenceAnswer(res.body.captcha).toString())
    }
  })
})

void describe('/api/Feedbacks rate limiting', () => {
  void it('POST responses carry rate limit headers to hinder large-scale automated CAPTCHA solving', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)

    const res = await request(app)
      .post('/api/Feedbacks')
      .set({ 'content-type': 'application/json' })
      .send({
        comment: 'Rate limit header check',
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['x-ratelimit-limit'], 'expected an X-RateLimit-Limit header on /api/Feedbacks responses')
    assert.equal(res.headers['x-ratelimit-limit'], '100')
  })
})
