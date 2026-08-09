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

// MarsDB is in-process but promise-based, so Node interleaves concurrent requests at every
// await. Removing the artificial delay narrowed the window but left it open: the "has this
// user already liked it" check and the write that records the like are still several awaits
// apart, and nothing stopped a second request from clearing the same check in between.
// Likes for one review are therefore queued here - a request only begins its read-check-write
// once the previous one for that review has finished its own, which makes the sequence one
// indivisible step for every writer of likedBy/likesCount (this handler is the only one).
const reviewLikeLocks = new Map<string, Promise<unknown>>()

async function withReviewLock<T> (reviewId: string, work: () => Promise<T>): Promise<T> {
  // Read and replace happen in the same tick, so two requests can never take the same slot.
  const previous = reviewLikeLocks.get(reviewId) ?? Promise.resolve()
  const current = previous.then(work, work)
  const tracked = current.then(() => undefined, () => undefined)
  reviewLikeLocks.set(reviewId, tracked)
  try {
    return await current
  } finally {
    // Only the last request in the queue clears the entry, so the map cannot grow forever.
    if (reviewLikeLocks.get(reviewId) === tracked) {
      reviewLikeLocks.delete(reviewId)
    }
  }
}

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    // The queue above is keyed by review id, so the id has to be a plain string: two object
    // ids would land on different keys and would not serialise against each other.
    if (typeof id !== 'string') {
      return res.status(400).json({ error: 'Wrong Params' })
    }

    try {
      await withReviewLock(id, async () => {
        const review = await db.reviewsCollection.findOne({ _id: id })
        if (!review) {
          res.status(404).json({ error: 'Not found' })
          return
        }

        const likedBy = review.likedBy
        if (likedBy.includes(user.data.email)) {
          res.status(403).json({ error: 'Not allowed' })
          return
        }

        await db.reviewsCollection.update(
          { _id: id },
          { $inc: { likesCount: 1 } }
        )

        // The check above and the write below have to be one logical step. The delay that
        // used to sit here held the window open long enough for a second request to pass
        // the same check before the first had recorded its like; the lock now holds every
        // other request for this review out until the like below has been recorded.
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
      })
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
