/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const id = typeof req.body.id === 'string' ? req.body.id : ''
    if (!user?.data || !id) {
      res.status(401).json({ error: 'Blocked illegal activity' })
      return
    }
    db.reviewsCollection.findOne({ _id: id }).then(
      (review: { author: any } | null) => {
        if (!review || review.author !== user.data.email) {
          res.status(403).json({ error: 'Blocked illegal activity' })
          return
        }
        db.reviewsCollection.update(
          { _id: id },
          { $set: { message: req.body.message } },
          {}
        ).then(
          (result: { modified: number }) => {
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
