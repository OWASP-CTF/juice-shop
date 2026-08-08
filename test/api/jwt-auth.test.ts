/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import jwt from 'jsonwebtoken'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const getUsers = (token: string) => request(app)
  .get('/api/Users')
  .set({ Authorization: `Bearer ${token}` })

const assertJwtChallengesUnsolved = () => {
  assert.equal(challenges.jwtUnsignedChallenge.solved, false)
  assert.equal(challenges.jwtForgedChallenge.solved, false)
}

void describe('JWT authentication', () => {
  void it('accepts a valid RS256 token without solving JWT challenges', async () => {
    const token = security.authorize({ data: { email: 'jwtn3d@juice-sh.op' } })

    const res = await getUsers(token)

    assert.equal(res.status, 200)
    assertJwtChallengesUnsolved()
  })

  void it('rejects an unsigned token before the protected handler', async () => {
    const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'

    const res = await getUsers(token)

    assert.equal(res.status, 401)
    assertJwtChallengesUnsolved()
  })

  void it('rejects an HS256 token signed with the RSA public key before the protected handler', async () => {
    const token = jwt.sign({ data: { email: 'rsa_lord@juice-sh.op' } }, security.publicKey, { algorithm: 'HS256' })

    const res = await getUsers(token)

    assert.equal(res.status, 401)
    assertJwtChallengesUnsolved()
  })

  void it('rejects a malformed token before the protected handler', async () => {
    const res = await getUsers('not-a-jwt')

    assert.equal(res.status, 401)
    assertJwtChallengesUnsolved()
  })
})
