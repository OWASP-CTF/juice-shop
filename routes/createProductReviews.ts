/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import { reviewsCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    // The author is the authenticated caller. A body-supplied author is ignored, so a
    // review cannot be attributed to somebody else, and the marker that used to compare
    // the body's author against the caller is gone with the flaw: it fired on the request
    // alone, before any review was written and even for callers with no session at all.
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message: req.body.message,
        author: user.data.email,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
