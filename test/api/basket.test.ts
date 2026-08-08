/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import * as db from '../../data/mongodb'
import { challenges } from '../../data/datacache'
import { BasketItemModel } from '../../models/basketitem'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

const validCoupon = security.generateCoupon(15)
const outdatedCoupon = security.generateCoupon(20, new Date(2001, 0, 1))
const tamperedCoupon = validCoupon.replace(':15.', ':75.')
const excessiveCoupon = validCoupon.replace(':15.', ':100.')

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  },
  { timeout: 60000 }
)

void describe('/rest/basket/:id', () => {
  void it('GET existing basket by id is not allowed via public API', async () => {
    const res = await request(app).get('/rest/basket/1')
    assert.equal(res.status, 401)
  })

  void it('GET a non-owned basket id is forbidden', async () => {
    const res = await request(app).get('/rest/basket/4711').set(authHeader)
    assert.equal(res.status, 403)
  })

  void it('GET existing basket with contained products by id', async () => {
    const res = await request(app).get('/rest/basket/2').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.id, 2)
    assert.ok(Array.isArray(res.body.data.Products))
  })

  void it.skip('GET basket should accept forged JWTs', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ data: { email: 'jim@juice-sh.op' }, iat: 1508639612, exp: 9999999999 })).toString('base64url')
    const unsignedToken = `${header}.${payload}.`
    const res = await request(app)
      .get('/rest/basket/1')
      .set({ Authorization: 'Bearer ' + unsignedToken, 'content-type': 'application/json' })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })
})

void describe('/api/Baskets', () => {
  void it('POST new basket is not part of API', async () => {
    const res = await request(app)
      .post('/api/Baskets')
      .set(authHeader)
      .send({ UserId: 1 })
    assert.equal(res.status, 500)
  })

  void it('GET all baskets is not part of API', async () => {
    const res = await request(app).get('/api/Baskets').set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/api/Baskets/:id', () => {
  void it('GET existing basket is not part of API', async () => {
    const res = await request(app).get('/api/Baskets/1').set(authHeader)
    assert.equal(res.status, 500)
  })

  void it('PUT update existing basket is not part of API', async () => {
    const res = await request(app)
      .put('/api/Baskets/1')
      .set(authHeader)
      .send({ UserId: 2 })
    assert.equal(res.status, 500)
  })

  void it('DELETE existing basket is not part of API', async () => {
    const res = await request(app).delete('/api/Baskets/1').set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/rest/basket/:id', () => {
  void it('GET existing basket of another user', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    challenges.basketAccessChallenge.solved = false
    const res = await request(app)
      .get('/rest/basket/2')
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 403)
    assert.equal(challenges.basketAccessChallenge.solved, false)
  })
})

void describe('/rest/basket/:id/checkout', () => {
  void it('POST placing an order for a basket is not allowed via public API', async () => {
    const res = await request(app).post('/rest/basket/1/checkout')
    assert.equal(res.status, 401)
  })

  void it('POST placing an order for an existing basket returns orderId', async () => {
    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST cannot place an order for another user\'s basket', async () => {
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader)
    assert.equal(res.status, 403)
  })

  void it('POST placing an order for a non-existing basket fails', async () => {
    const res = await request(app).post('/rest/basket/42/checkout').set(authHeader)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Basket with id=42 does not exist.'))
  })

  void it('POST rejects a basket with a negative quantity without solving the challenge', async () => {
    challenges.negativeOrderChallenge.solved = false
    const invalidItem = await BasketItemModel.create({ BasketId: 2, ProductId: 10, quantity: -100 })
    try {
      const res = await request(app).post('/rest/basket/2/checkout').set(authHeader)
      assert.equal(res.status, 400)
      assert.equal(challenges.negativeOrderChallenge.solved, false)
    } finally {
      await invalidItem.destroy()
    }
  })

  void it('POST ignores forged historical campaign data without solving coupon challenges', async () => {
    challenges.forgedCouponChallenge.solved = false
    challenges.manipulateClockChallenge.solved = false
    const couponData = Buffer.from('WMNSDY2019-1551999600000').toString('base64')

    const res = await request(app)
      .post('/rest/basket/2/checkout')
      .set(authHeader)
      .send({ couponData })
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)

    const order = await db.ordersCollection.findOne({ orderId: res.body.orderConfirmation })
    assert.equal(order.promotionalAmount, '0')
    assert.equal(challenges.forgedCouponChallenge.solved, false)
    assert.equal(challenges.manipulateClockChallenge.solved, false)
  })
})

void describe('/rest/basket/:id/coupon/:coupon', () => {
  void it('PUT apply valid coupon to existing basket', async () => {
    challenges.forgedCouponChallenge.solved = false
    const res = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.discount, 15)
    assert.equal(challenges.forgedCouponChallenge.solved, false)
  })

  void it('PUT rejects a coupon whose signed discount was changed', async () => {
    challenges.forgedCouponChallenge.solved = false
    const res = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(tamperedCoupon))
      .set(authHeader)
    assert.equal(res.status, 404)
    assert.equal(challenges.forgedCouponChallenge.solved, false)
  })

  void it('PUT rejects an over-100 coupon value', async () => {
    challenges.forgedCouponChallenge.solved = false
    const res = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(excessiveCoupon))
      .set(authHeader)
    assert.equal(res.status, 404)
    assert.equal(challenges.forgedCouponChallenge.solved, false)
  })

  void it('PUT apply invalid coupon is not accepted', async () => {
    const res = await request(app)
      .put('/rest/basket/2/coupon/xxxxxxxxxx')
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply outdated coupon is not accepted', async () => {
    const res = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(outdatedCoupon))
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply valid coupon to non-existing basket throws error', async () => {
    const res = await request(app)
      .put('/rest/basket/4711/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 500)
  })

  void it('PUT cannot apply a coupon to another user\'s basket', async () => {
    const res = await request(app)
      .put('/rest/basket/1/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 403)
  })
})
