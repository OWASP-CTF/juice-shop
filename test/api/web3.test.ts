/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'
import { type UserModel } from '../../models/user'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

const skipReason = process.env.ALCHEMY_API_KEY ? undefined : 'ALCHEMY_API_KEY not set'

before(async () => {
  if (!process.env.ALCHEMY_API_KEY) return
  const result = await createTestApp()
  app = result.app
  const token = security.authorize({ data: { id: 1 } })
  security.authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })
  authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/submitKey', { skip: skipReason }, () => {
  void it('POST requires authentication', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .send({ privateKey: '0x5bcc3e9d38baa06e7bfaab80ae5957bbe8ef059e640311d7d6d465e6bc948e3e' })

    assert.equal(res.status, 401)
    assert.equal(res.body.error, 'Authentication required')
  })

  void it('POST missing key in request body gets rejected as non-Ethereum key', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .set(authHeader)
      .send({})

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Looks like you entered a non-Ethereum private key to access me.')
  })

  void it('POST arbitrary string in request body gets rejected as non-Ethereum key', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .set(authHeader)
      .send({ privateKey: 'lalalala' })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Looks like you entered a non-Ethereum private key to access me.')
  })

  void it('POST previously exposed private key is rejected', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .set(authHeader)
      .send({ privateKey: '0x5bcc3e9d38baa06e7bfaab80ae5957bbe8ef059e640311d7d6d465e6bc948e3e' })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Looks like you entered a non-Ethereum private key to access me.')
  })
})

void describe('/nftUnlocked', { skip: skipReason }, () => {
  void it('GET requires authentication', async () => {
    const res = await request(app)
      .get('/rest/web3/nftUnlocked')

    assert.equal(res.status, 401)
    assert.equal(res.body.error, 'Authentication required')
  })

  void it('GET solution status of "Unlock NFT" challenge', async () => {
    const res = await request(app)
      .get('/rest/web3/nftUnlocked')
      .set(authHeader)

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
