/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/ftp', () => {
  void it('GET does not expose a directory listing', async () => {
    const res = await request(app)
      .get('/ftp')

    assert.equal(res.status, 401)
    assert.ok(!res.text.includes('<title>listing directory /ftp</title>'))
  })

  void it('GET does not expose confidential files or solve the directory listing challenge', async () => {
    challenges.directoryListingChallenge.solved = false

    const res = await request(app)
      .get('/ftp/acquisitions.md')

    assert.equal(res.status, 401)
    assert.ok(!res.text.includes('# Planned Acquisitions'))
    assert.equal(challenges.directoryListingChallenge.solved, false)
  })

  void it('GET does not expose quarantined files', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_linux_amd_64.url')

    assert.equal(res.status, 401)
  })
})
