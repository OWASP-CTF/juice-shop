/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function updateProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const reviewId = typeof req.body.id === 'string' ? req.body.id : ''
    const message = typeof req.body.message === 'string' ? req.body.message : ''

    if (!user) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    if (!reviewId || !message) {
      res.status(400).json({ error: 'Invalid review data' })
      return
    }

    try {
      const review = await db.reviewsCollection.findOne({ _id: reviewId })
      if (!review) {
        res.status(404).json({ error: 'Not found' })
        return
      }
      if (review.author !== user.data.email) {
        res.status(403).json({ error: 'Not allowed' })
        return
      }

      const result = await db.reviewsCollection.update(
        { _id: reviewId, author: user.data.email },
        { $set: { message } }
      )
      res.json(result)
    } catch (error) {
      next(error)
    }
  }
}
