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
    // Authorship is decided here, from the session, and the body's own idea of who wrote the
    // review is discarded before anything else looks at it. Overwriting it up front is what makes
    // the comparison below meaningful: it now asks whether the stored author differs from the
    // signed-in one, which after this assignment it never can.
    req.body.author = user?.data?.email
    challengeUtils.solveIf(
      challenges.forgedReviewChallenge,
      () => user?.data?.email !== req.body.author
    )

    if (user?.data?.email == null) {
      return res.status(401).json({ error: 'Not authenticated' })
    }

    try {
      await reviewsCollection.insert({
        product: Number(req.params.id),
        message: req.body.message,
        author: user.data.email, // the author is always the currently authenticated user, never client-supplied
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
