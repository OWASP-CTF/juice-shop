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
import { UserModel } from '../../models/user'

const repositoryKnownTotpSecret = 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'

const knownCredentials = [
  ['JUICE_SHOP_ADMIN_PASSWORD', 'admin', 'admin123'],
  ['JUICE_SHOP_GOOGLE_USER_PASSWORD', 'bjoern.kimminich@gmail.com', 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='],
  ['JUICE_SHOP_SUPPORT_PASSWORD', 'support', 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'],
  ['JUICE_SHOP_RAPPER_PASSWORD', 'mc.safesearch', 'Mr. N00dles'],
  ['JUICE_SHOP_JANNIK_PASSWORD', 'J12934', '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'],
  ['JUICE_SHOP_2FA_ADMIN_PASSWORD', 'wurstbrot', 'EinBelegtesBrotMitSchinkenSCHINKEN!'],
  ['JUICE_SHOP_AMY_PASSWORD', 'amy', 'K1f.....................'],
  ['JUICE_SHOP_TEST_USER_PASSWORD', 'testing', 'IamUsedForTesting']
] as const

let app: Express

before(async () => {
  for (const [environmentVariable] of knownCredentials) delete process.env[environmentVariable]
  delete process.env.JUICE_SHOP_2FA_ADMIN_TOTP_SECRET
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('production seed credentials', () => {
  for (const [, user, password] of knownCredentials) {
    void it(`rejects the repository-known password for ${user}`, async () => {
      const email = user.includes('@') ? user : `${user}@${config.get<string>('application.domain')}`
      const res = await request(app)
        .post('/rest/user/login')
        .send({ email, password })

      assert.equal(res.status, 401)
    })
  }

  void it('replaces the repository-known 2FA seed', async () => {
    const user = await UserModel.findOne({ where: { email: `wurstbrot@${config.get<string>('application.domain')}` } })

    assert.ok(user)
    assert.notEqual(user.totpSecret, repositoryKnownTotpSecret)
    assert.match(user.totpSecret, /^[A-Z2-7]{32}$/)
  })
})
