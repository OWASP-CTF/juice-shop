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
    // The author is the authenticated caller. A body-supplied author is ignored, so a
    // review cannot be attributed to somebody else.
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    const email = user.data.email

    try {
      const inserted = await reviewsCollection.insert({
        product: req.params.id,
        message: req.body.message,
        author: email,
        likesCount: 0,
        likedBy: []
      })
      // Solve only if a review actually ended up attributed to someone other than
      // the caller, matching what was persisted rather than the raw request body.
      challengeUtils.solveIf(
        challenges.forgedReviewChallenge,
        () => inserted?.author !== undefined && inserted.author !== email
      )
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
