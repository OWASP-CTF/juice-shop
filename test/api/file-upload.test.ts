/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import fs from 'node:fs'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { challenges } from '../../data/datacache'
import { createTestApp } from './helpers/setup'

let app: Express

function resetUnsafeUploadChallenges () {
  challenges.deprecatedInterfaceChallenge.solved = false
  challenges.fileWriteChallenge.solved = false
  challenges.xxeDosChallenge.solved = false
  challenges.xxeFileDisclosureChallenge.solved = false
  challenges.yamlBombChallenge.solved = false
}

function assertUnsafeUploadChallengesUnsolved () {
  assert.equal(challenges.deprecatedInterfaceChallenge.solved, false)
  assert.equal(challenges.fileWriteChallenge.solved, false)
  assert.equal(challenges.xxeDosChallenge.solved, false)
  assert.equal(challenges.xxeFileDisclosureChallenge.solved, false)
  assert.equal(challenges.yamlBombChallenge.solved, false)
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/file-upload', () => {
  void it('POST file valid PDF for client and API', async () => {
    const file = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file too large for client validation but valid for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file with illegal type for client validation but valid for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidTypeForClient.exe')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file type XML deprecated for API', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/deprecatedTypeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST large XML file near upload size limit', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/maxSizeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST file type XML with XXE attack against Windows is rejected without parsing', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/xxeForWindows.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST file type XML with XXE attack against Linux is rejected without parsing', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/xxeForLinux.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST file type XML with Billion Laughs attack is rejected without parsing', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/xxeBillionLaughs.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST file type XML with Quadratic Blowup attack is rejected without parsing', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/xxeQuadraticBlowup.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST file type XML with dev/random attack is rejected without parsing', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/xxeDevRandom.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST file type YAML with Billion Laughs-style attack is rejected without parsing', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/yamlBomb.yml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST file too large for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForServer.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 500)
  })

  void it('POST zip file with directory traversal payload cannot escape the upload directory', async () => {
    resetUnsafeUploadChallenges()
    const file = path.resolve(__dirname, '../files/arbitraryFileWrite.zip')
    const protectedFile = path.resolve(__dirname, '../../ftp/legal.md')
    const originalContents = await fs.promises.readFile(protectedFile)
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
    await delay(100)
    assert.deepEqual(await fs.promises.readFile(protectedFile), originalContents)
    assertUnsafeUploadChallengesUnsolved()
  })

  void it('POST zip file with password protection', async () => {
    const file = path.resolve(__dirname, '../files/passwordProtected.zip')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST valid file with tampered content length', { skip: 'Fails on CI/CD pipeline' }, async () => {
    const file = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .set('Content-Length', '42')
      .attach('file', file)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected end of form'))
  })
})
