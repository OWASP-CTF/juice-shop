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

void describe('/redirect', () => {
  void it('GET redirected to https://github.com/juice-shop/juice-shop when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=https://github.com/juice-shop/juice-shop')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET rejects outdated blockchain.info cryptocurrency target', async () => {
    const res = await request(app)
      .get('/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm')
      .redirects(0)
    assert.equal(res.status, 406)
  })

  void it('GET redirected to http://shop.spreadshirt.com/juiceshop when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=http://shop.spreadshirt.com/juiceshop')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET redirected to http://shop.spreadshirt.de/juiceshop when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=http://shop.spreadshirt.de/juiceshop')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET redirected to https://www.stickeryou.com/products/owasp-juice-shop/794 when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=https://www.stickeryou.com/products/owasp-juice-shop/794')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET rejects outdated dash cryptocurrency target', async () => {
    const res = await request(app)
      .get('/redirect?to=https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW')
      .redirects(0)
    assert.equal(res.status, 406)
  })

  void it('GET rejects outdated etherscan cryptocurrency target', async () => {
    const res = await request(app)
      .get('/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6')
      .redirects(0)
    assert.equal(res.status, 406)
  })

  void it('GET rejects /redirect without a target without information leakage', async () => {
    const res = await request(app)
      .get('/redirect')
    assert.equal(res.status, 406)
    assert.equal(res.text.includes('TypeError'), false)
  })

  void it('GET rejects /redirect with an unrelated parameter without information leakage', async () => {
    const res = await request(app)
      .get('/redirect?x=y')
    assert.equal(res.status, 406)
    assert.equal(res.text.includes('TypeError'), false)
  })

  void it('GET rejects an unrecognized redirect target without leaking validation details', async () => {
    const res = await request(app)
      .get('/redirect?to=whatever')
    assert.equal(res.status, 406)
    assert.deepEqual(res.body, { error: 'The request could not be processed.' })
    assert.equal(res.text.includes('whatever'), false)
  })

  void it('GET rejects a target that merely contains an allow-listed URL', async () => {
    const res = await request(app)
      .get('/redirect?to=/score-board?satisfyIndexOf=https://github.com/juice-shop/juice-shop')
      .redirects(1)
    assert.equal(res.status, 406)
  })
})
