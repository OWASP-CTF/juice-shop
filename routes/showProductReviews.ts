/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from 'data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // The product id is a numeric primary key: reject anything else instead of
    // handing it to the database as an expression.
    const rawId = String(req.params.id)
    if (!/^\d+$/.test(rawId)) {
      res.status(400).json({ error: 'Wrong Params' })
      return
    }
    const id = Number.parseInt(rawId, 10)

    // Measure how long the query takes, to check if there was a nosql dos attack
    const t0 = new Date().getTime()

    // Reviews seeded at startup store `product` as a number, reviews created through
    // the API store it as the string from the URL, so both spellings are matched.
    db.reviewsCollection.find({ product: { $in: [id, String(id)] } }).then((reviews: Review[]) => {
      const t1 = new Date().getTime()
      challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return (t1 - t0) > 2000 })
      const user = security.authenticatedUsers.from(req)
      for (let i = 0; i < reviews.length; i++) {
        if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
          reviews[i].liked = true
        }
      }
      res.json(utils.queryResultToJson(reviews))
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}
