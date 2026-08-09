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

const skipReason = process.env.ALCHEMY_API_KEY ? undefined : 'ALCHEMY_API_KEY not set'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/submitKey', () => {
  void it('POST is not exposed, including for the formerly accepted private-key payload', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .send({ privateKey: '0x5bcc3e9d38baa06e7bfaab80ae5957bbe8ef059e640311d7d6d465e6bc948e3e' })

    assert.equal(res.status, 404)
  })
})

void describe('/nftUnlocked', { skip: skipReason }, () => {
  void it('GET solution status of "Unlock NFT" challenge', async () => {
    const res = await request(app)
      .get('/rest/web3/nftUnlocked')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.status, 'boolean')
  })
})

void describe('/nftMintListen', { skip: skipReason }, () => {
  void it('GET call confirms registration of event listener', async () => {
    const res = await request(app)
      .get('/rest/web3/nftMintListen')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  })
})

void describe('/walletNFTVerify', { skip: skipReason }, () => {
  void it('POST missing wallet address fails to solve minting challenge', async () => {
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .send({})

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Wallet did not mint the NFT')
  })

  void it('POST invalid wallet address fails to solve minting challenge', async () => {
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .send({ walletAddress: 'lalalalala' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Wallet did not mint the NFT')
  })
})

void describe('/walletExploitAddress', { skip: skipReason }, () => {
  void it('POST missing wallet address in request body still leads to success notification', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({})

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  })

  void it('POST invalid wallet address in request body still leads to success notification', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: 'lalalalala' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  })

  void it('POST self-referential address in request body leads to success notification', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: '0x413744D59d31AFDC2889aeE602636177805Bd7b0' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  })
})
