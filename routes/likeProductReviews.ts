/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function likeProductReviews () {
  return async (req: Request, res: Response) => {
    const id = typeof req.body.id === 'string' ? req.body.id : ''
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    if (!id || id.length > 100) {
      return res.status(400).json({ error: 'Wrong Params' })
    }

    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      const likedBy = review.likedBy
      if (likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      await db.reviewsCollection.update(
        { _id: id },
        { $inc: { likesCount: 1 } }
      )

      try {
        const updatedReview = await db.reviewsCollection.findOne({ _id: id })
        if (!updatedReview) {
          return res.status(404).json({ error: 'Not found' })
        }
        const updatedLikedBy = [...updatedReview.likedBy]
        updatedLikedBy.push(user.data.email)

        const result = await db.reviewsCollection.update(
          { _id: id },
          { $set: { likedBy: updatedLikedBy } }
        )
        res.json(result)
      } catch (err) {
        res.status(500).json(err)
      }
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
