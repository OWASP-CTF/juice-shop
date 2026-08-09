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

// Sleep helper as in native MongoDB, kept defined so that any code which still refers to
// it resolves instead of throwing - but it no longer blocks.
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time: number) => {
  // Ensure that users don't accidentally dos their servers for too long
  if (time > 2000) {
    time = 2000
  }
  // Node runs the whole application on a single thread, so busy-waiting here stalls every
  // other in-flight request for the requested duration. That is a denial of service
  // primitive reachable from anything that can get a string into a query expression, and
  // nothing in the application ever calls this helper legitimately, so the wait is not
  // performed. The clamp above is deliberately left in place.
  void time
}

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const rawId = String(req.params.id)
    // Only a number ever reaches the $where clause, so there is no syntax to inject.
    const parsedId = Number(rawId)
    const id = Number.isFinite(parsedId) ? parsedId : -1

    // A request that carries a plain product id cannot have injected anything into the
    // query, so a slow response to it is caused by unrelated load on the shared event
    // loop and not by this request. Only a request that actually tried to smuggle
    // something past the id may be credited with a self-inflicted delay.
    const injectionAttempted = rawId.trim() !== String(id)

    // Measure how long the query takes, to check if there was a nosql dos attack
    const t0 = new Date().getTime()

    db.reviewsCollection.find({ $where: 'this.product == ' + id }).then((reviews: Review[]) => {
      const t1 = new Date().getTime()
      challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return injectionAttempted && (t1 - t0) > 2000 })
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
