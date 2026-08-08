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

// Blocking sleep function as in native MongoDB
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time: number) => {
  // Ensure that users don't accidentally dos their servers for too long
  if (time > 2000) {
    time = 2000
  }
  const stop = new Date().getTime()
  while (new Date().getTime() < stop + time) {
    ;
  }
}

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Never build a $where clause from user input, which would otherwise allow arbitrary
    // JS execution against the NoSQL store. Seeded reviews store `product` as a Number
    // while reviews created through the API store it as the raw route param String, so
    // (unlike the old loosely-typed `==` comparison in $where) match both types explicitly
    // instead of trusting/interpolating any user-controlled operators.
    const rawId = req.params.id
    const numericId = Number(rawId)
    const idFilter = Number.isNaN(numericId) ? { product: rawId } : { $or: [{ product: rawId }, { product: numericId }] }

    // Measure how long the query takes, to check if there was a nosql dos attack
    const t0 = new Date().getTime()

    db.reviewsCollection.find(idFilter).then((reviews: Review[]) => {
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
