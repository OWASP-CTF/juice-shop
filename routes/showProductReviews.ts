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

// The blocking sleep helper that used to be published on the global object has been dropped
// along with the query evaluation that was its only caller. Handing every piece of evaluated
// query text a primitive whose whole purpose is to stall the event loop is a denial of service
// waiting to be reached; nothing that runs here needs it.

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // The product is selected by value rather than by a snippet of JavaScript built around the
    // request parameter. A selector is data the database matches; an expression is code the
    // database runs, and there is no way to write untrusted input into code safely enough that
    // it is worth doing when a plain equality match answers the same question.
    const id = Number(req.params.id)

    // Measure how long the query takes, to check if there was a nosql dos attack
    const t0 = new Date().getTime()

    db.reviewsCollection.find({ product: id }).then((reviews: Review[]) => {
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
