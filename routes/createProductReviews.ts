/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { reviewsCollection } from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    /* A review is attributed to whoever is logged in, and to nobody in particular when the
       request is anonymous. The author never comes from the request body any more, so a review
       cannot be filed under somebody else's name. */
    const author = user?.data?.email ?? 'Anonymous'
    challengeUtils.solveIf(
      challenges.forgedReviewChallenge,
      () => user?.data?.email !== undefined && user.data.email !== author
    )

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message: req.body.message,
        author,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
