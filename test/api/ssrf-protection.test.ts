import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import config from 'config'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/profile/image/url', () => {
  void it('rejects loopback image URLs before fetching', async () => {
    const { token } = await login(app, { email: `jim@${config.get<string>('application.domain')}`, password: 'ncc-1701' })
    const res = await request(app).post('/profile/image/url').set('Cookie', `token=${token}`).field('imageUrl', 'http://127.0.0.1:3000/solve/challenges/server-side').redirects(0)
    assert.equal(res.status, 400)
  })
})
