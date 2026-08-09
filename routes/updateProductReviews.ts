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
    // `id` was passed straight into a NoSQL query as-is: a client could submit an object
    // (e.g. { "$ne": null }) instead of a string, turning it into a query operator that
    // matches (and with { multi: true }, updates) every review in the collection - not just
    // the caller's own. Require a plain string id, and verify the review actually belongs to
    // the authenticated user before allowing the edit.
    if (typeof req.body.id !== 'string' || !user?.data) {
      res.status(400).json({ error: 'Invalid review id' })
      return
    }
    db.reviewsCollection.findOne({ _id: req.body.id }).then(
      (review: { author: any } | null) => {
        if (!review) {
          res.status(404).json({ error: 'Not found' })
          return
        }
        if (review.author !== user.data.email) {
          res.status(403).json({ error: 'Not allowed to edit this review' })
          return
        }
        db.reviewsCollection.update(
          { _id: req.body.id },
          { $set: { message: req.body.message } },
          { multi: false }
        ).then(
          (result: { modified: number, original: Array<{ author: any }> }) => {
            challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 })
            challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 })
            res.json(result)
          }, (err: unknown) => {
            res.status(500).json(err)
          })
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
