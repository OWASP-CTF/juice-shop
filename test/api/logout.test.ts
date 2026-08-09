import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  app = (await createTestApp()).app
}, { timeout: 60000 })

void describe('/rest/user/logout', () => {
  void it('revokes the logged-out token while a fresh token remains usable', async () => {
    const credentials = { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' }
    const { token } = await login(app, credentials)

    const logout = await request(app)
      .post('/rest/user/logout')
      .set('Authorization', 'Bearer ' + token)
    assert.equal(logout.status, 204)

    const replay = await request(app)
      .get('/api/Users')
      .set('Authorization', 'Bearer ' + token)
    assert.equal(replay.status, 401)

    const { token: adminToken } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
    await request(app)
      .post('/rest/user/logout')
      .set('Authorization', 'Bearer ' + adminToken)
      .expect(204)
    const privilegedReplay = await request(app)
      .get('/metrics')
      .set('Authorization', 'Bearer ' + adminToken)
    assert.equal(privilegedReplay.status, 403)

    const { token: freshToken } = await login(app, credentials)
    const fresh = await request(app)
      .get('/api/Users')
      .set('Authorization', 'Bearer ' + freshToken)
    assert.equal(fresh.status, 200)
  })
})
