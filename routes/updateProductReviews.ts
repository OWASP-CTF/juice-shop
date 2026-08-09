/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    // Only accept primitive string ids so query operators like {"$ne": ...}
    // can never reach the MongoDB filter (NoSQL injection).
    if (typeof req.body.id !== 'string') {
      res.status(400).json({ error: 'Invalid review id' })
      return
    }
    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
      // Scope the update to a single review owned by the authenticated user
      // so reviews of other users cannot be modified (broken access control).
      { _id: req.body.id, author: user.data.email },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
