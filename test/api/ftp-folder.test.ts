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

void describe('/ftp', () => {
  void it('does not expose a directory listing', async () => {
    const res = await request(app).get('/ftp')
    assert.equal(res.status, 404)
  })

  void it('serves the public legal document', async () => {
    const res = await request(app).get('/ftp/legal.md')
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('# Legal Information'))
  })

  for (const file of [
    'acquisitions.md',
    'incident-support.kdbx',
    'eastere.gg%2500.md',
    'suspicious_errors.yml%2500.md',
    'coupons_2013.md.bak%2500.md',
    'package.json.bak%2500.md'
  ]) {
    void it(`does not serve sensitive file ${file}`, async () => {
      const res = await request(app).get('/ftp/' + file)
      assert.equal(res.status, 403)
    })
  }

  void it('does not serve quarantined malware artifacts', async () => {
    const res = await request(app).get('/ftp/quarantine/juicy_malware_linux_amd_64.url')
    assert.equal(res.status, 404)
  })
})
