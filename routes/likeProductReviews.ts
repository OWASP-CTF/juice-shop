/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
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

      // The check above and the write below have to be one logical step. The delay that
      // used to sit here held the window open long enough for a second request to pass
      // the same check before the first had recorded its like.
      try {
        const updatedReview: Review = await db.reviewsCollection.findOne({ _id: id })
        const updatedLikedBy = updatedReview.likedBy
        updatedLikedBy.push(user.data.email)

        const count = updatedLikedBy.filter(email => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

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
