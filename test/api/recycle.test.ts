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

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let otherUserAuthHeader: { Authorization: string, 'content-type': string }
let addressId: number
let recycleId: number
let ownerId: number

before(async () => {
  const result = await createTestApp()
  app = result.app

  const authentication = await login(app, {
    email: 'jim@juice-sh.op',
    password: 'ncc-1701'
  })
  ownerId = (security.decode(authentication.token) as any).data.id
  authHeader = { Authorization: `Bearer ${authentication.token}`, 'content-type': 'application/json' }

  const otherAuthentication = await login(app, {
    email: 'bjoern.kimminich@gmail.com',
    password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
  })
  otherUserAuthHeader = { Authorization: `Bearer ${otherAuthentication.token}`, 'content-type': 'application/json' }

  const address = await request(app).post('/api/Addresss').set(authHeader).send({
    fullName: 'Jim',
    mobileNum: '9800000000',
    zipCode: 'NX 101',
    streetAddress: 'Bakers Street',
    city: 'NYC',
    state: 'NY',
    country: 'USA'
  })
  assert.equal(address.status, 201)
  addressId = address.body.data.id

  const recycle = await request(app)
    .post('/api/Recycles')
    .set(authHeader)
    .send({
      UserId: 1,
      quantity: 200,
      AddressId: addressId,
      isPickup: true,
      date: '2017-05-31'
    })
  assert.equal(recycle.status, 201)
  assert.equal(recycle.body.data.UserId, ownerId)
  recycleId = recycle.body.data.id
}, { timeout: 60000 })

void describe('/api/Recycles', () => {
  void it('POST new recycle derives its owner from the authenticated user', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        UserId: 1,
        quantity: 200,
        AddressId: addressId,
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, ownerId)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('GET recycles is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Recycles')
    assert.equal(res.status, 401)
  })

  void it('GET returns only the authenticated user\'s recycles', async () => {
    const res = await request(app)
      .get('/api/Recycles')
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(res.body.data.length >= 1)
    assert.equal(res.body.data.every((item: any) => item.UserId === ownerId), true)
  })

  void it('GET own existing recycle from this endpoint', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${recycleId}`)
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.ok(Array.isArray(items))
    for (const item of items) {
      assert.equal(typeof item.id, 'number')
      assert.equal(typeof item.UserId, 'number')
      assert.equal(typeof item.AddressId, 'number')
      assert.equal(typeof item.quantity, 'number')
      assert.equal(typeof item.isPickup, 'boolean')
      assert.ok(item.date !== undefined)
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('GET a recycle owned by another user is not allowed', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${recycleId}`)
      .set(otherUserAuthHeader)
    assert.equal(res.status, 404)
  })

  void it('POST cannot attach a recycle to another user\'s address', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(otherUserAuthHeader)
      .send({ quantity: 100, AddressId: addressId, isPickup: false, date: '2017-06-01' })
    assert.equal(res.status, 403)
  })

  void it('PUT update existing recycle is forbidden', async () => {
    const res = await request(app)
      .put('/api/Recycles/1')
      .set(authHeader)
      .send({
        quantity: 100000
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing recycle is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Recycles/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
