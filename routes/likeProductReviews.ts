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

const sleep = async (ms: number) => await new Promise(resolve => setTimeout(resolve, ms))

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

      // Claim the like in a single conditional write. The previous form read
      // likedBy, checked it, and only wrote it back after an await and a 150ms
      // sleep, so concurrent requests all passed the check and each appended
      // the same address; the closing $set was last-writer-wins as well.
      const claimed = await db.reviewsCollection.update(
        { _id: id, likedBy: { $ne: user.data.email } },
        { $push: { likedBy: user.data.email }, $inc: { likesCount: 1 } }
      )
      if (!claimed?.modified) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      // Artificial wait for timing attack challenge
      await sleep(150)
      try {
        const updatedReview: Review = await db.reviewsCollection.findOne({ _id: id })
        const updatedLikedBy = updatedReview.likedBy

        const count = updatedLikedBy.filter((email: string) => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

        res.json(claimed)
      } catch (err) {
        res.status(500).json(err)
      }
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
