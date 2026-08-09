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
    // Authenticated users can never author a review under someone else's identity.
    // Only genuinely anonymous (unauthenticated) requests fall back to the client-supplied name.
    const author = user?.data?.email ?? req.body.author

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
