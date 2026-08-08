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
import { challenges } from '../../data/datacache'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/products/:id/reviews', () => {
  void it('GET product reviews by product id', async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const review = res.body.data[0]
    assert.equal(typeof review.product, 'number')
    assert.equal(typeof review.message, 'string')
    assert.equal(typeof review.author, 'string')
  })

  void it('GET rejects a MongoDB command without evaluating it or solving the challenge', async () => {
    challenges.noSqlCommandChallenge.solved = false
    const res = await request(app)
      .get('/rest/products/sleep(1)/reviews')
    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.deepEqual(res.body, { error: 'Wrong Params' })
    assert.equal(challenges.noSqlCommandChallenge.solved, false)
  })

  void it('GET rejects an alphanumeric product id', async () => {
    const res = await request(app)
      .get('/rest/products/kaboom/reviews')
    assert.equal(res.status, 400)
  })

  void it('PUT single product review can be created', async () => {
    const message = 'Anonymous review with server-owned author'
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message,
        author: 'Anonymous'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))

    const reviews = await request(app).get('/rest/products/1/reviews')
    const createdReview = reviews.body.data.find((review: { message: string }) => review.message === message)
    assert.ok(createdReview)
    assert.equal(createdReview.author, 'Anonymous')
  })

  void it('PUT anonymous product review ignores a forged author', async () => {
    const message = 'Anonymous review with forged author'
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message,
        author: 'admin@juice-sh.op'
      })
    assert.equal(res.status, 201)

    const reviews = await request(app).get('/rest/products/1/reviews')
    const createdReview = reviews.body.data.find((review: { message: string }) => review.message === message)
    assert.ok(createdReview)
    assert.equal(createdReview.author, 'Anonymous')
    assert.equal(challenges.forgedReviewChallenge.solved, false)
  })

  void it('PUT authenticated product review ignores a forged author', async () => {
    const email = 'bjoern.kimminich@gmail.com'
    const message = 'Authenticated review with forged author'
    const { token } = await login(app, {
      email,
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        message,
        author: 'admin@juice-sh.op'
      })
    assert.equal(res.status, 201)

    const reviews = await request(app).get('/rest/products/1/reviews')
    const createdReview = reviews.body.data.find((review: { message: string }) => review.message === message)
    assert.ok(createdReview)
    assert.equal(createdReview.author, email)
    assert.equal(challenges.forgedReviewChallenge.solved, false)
  })
})

void describe('/rest/products/reviews', () => {
  let reviewId: string
  let reviewOwnerToken: string
  const ownedReviewMessage = `Review ownership fixture ${Date.now()}`

  before(async () => {
    const owner = await login(app, {
      email: 'mc.safesearch@juice-sh.op',
      password: 'Mr. N00dles'
    })
    reviewOwnerToken = owner.token
    const createRes = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${reviewOwnerToken}` })
      .send({ message: ownedReviewMessage })
    assert.equal(createRes.status, 201)

    const reviews = await request(app).get('/rest/products/1/reviews')
    const review = reviews.body.data.find((candidate: { message: string }) => candidate.message === ownedReviewMessage)
    assert.ok(review)
    reviewId = review._id
  })

  void it('PATCH single product review can be edited', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${reviewOwnerToken}` })
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.modified, 1)
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))

    const reviews = await request(app).get('/rest/products/1/reviews')
    const updatedReview = reviews.body.data.find((candidate: { _id: string }) => candidate._id === reviewId)
    assert.equal(updatedReview.message, 'Lorem Ipsum')
  })

  void it('PATCH single product review editing need an authenticated user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 401)
  })

  void it('PATCH cannot edit another user\'s review', async () => {
    challenges.forgedReviewChallenge.solved = false
    const foreignUser = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${foreignUser.token}` })
      .send({ id: reviewId, message: 'Forged edit' })

    assert.equal(res.status, 200)
    assert.equal(res.body.modified, 0)
    const reviews = await request(app).get('/rest/products/1/reviews')
    const unchangedReview = reviews.body.data.find((candidate: { _id: string }) => candidate._id === reviewId)
    assert.equal(unchangedReview.message, 'Lorem Ipsum')
    assert.equal(challenges.forgedReviewChallenge.solved, false)
  })

  void it('POST non-existing product review cannot be liked', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: 'does not exist'
      })
    assert.equal(res.status, 404)
  })

  void it('POST single product review can be liked', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: reviewId
      })
    assert.equal(res.status, 200)
  })

  void it('POST a product review cannot be liked repeatedly by the same user', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: reviewId
      })
    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Already liked')
  })

  void it('POST parallel likes from one user increment a review only once', async () => {
    const email = 'mc.safesearch@juice-sh.op'
    const message = `Parallel like regression ${Date.now()}`
    const { token } = await login(app, {
      email,
      password: 'Mr. N00dles'
    })

    const createRes = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({ message })
    assert.equal(createRes.status, 201)

    const reviewsBefore = await request(app).get('/rest/products/1/reviews')
    const review = reviewsBefore.body.data.find((candidate: { message: string }) => candidate.message === message)
    assert.ok(review)
    challenges.timingAttackChallenge.solved = false

    const responses = await Promise.all(Array.from({ length: 10 }, async () => await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({ id: review._id })))

    assert.ok(responses.some(res => res.status === 200))
    assert.ok(responses.every(res => res.status === 200 || res.status === 403))

    const reviewsAfter = await request(app).get('/rest/products/1/reviews')
    const updatedReview = reviewsAfter.body.data.find((candidate: { _id: string }) => candidate._id === review._id)
    assert.equal(updatedReview.likesCount, 1)
    assert.equal(updatedReview.likedBy.filter((likedBy: string) => likedBy === email).length, 1)
    assert.equal(challenges.timingAttackChallenge.solved, false)
  })

  void it('POST rejects a non-string review id', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({ id: { $ne: '' } })
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Wrong Params')
  })

  void it('PATCH rejects a selector injection without updating reviews', async () => {
    challenges.noSqlReviewsChallenge.solved = false
    challenges.forgedReviewChallenge.solved = false
    const before = await request(app).get('/rest/products/1/reviews')
    const snapshot = before.body.data.map((review: { _id: string, message: string }) => ({ _id: review._id, message: review.message }))
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${reviewOwnerToken}` })
      .send({
        id: { $ne: -1 },
        message: 'trololololololololololololololololololololololololololol'
      })
    assert.equal(res.status, 400)
    const after = await request(app).get('/rest/products/1/reviews')
    const current = after.body.data.map((review: { _id: string, message: string }) => ({ _id: review._id, message: review.message }))
    assert.deepEqual(current, snapshot)
    assert.equal(challenges.noSqlReviewsChallenge.solved, false)
    assert.equal(challenges.forgedReviewChallenge.solved, false)
  })
})
