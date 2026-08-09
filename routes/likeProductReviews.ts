/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const result = await db.reviewsCollection.update(
        { _id: id, likedBy: { $ne: user.data.email } },
        { $inc: { likesCount: 1 }, $addToSet: { likedBy: user.data.email } }
      )
      const modified = (result as any)?.nModified ?? (result as any)?.modified ?? 0
      challengeUtils.solveIf(challenges.timingAttackChallenge, () => modified > 1)
      if (!modified) {
        return res.status(403).json({ error: 'Not allowed' })
      }
      res.json(result)
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
