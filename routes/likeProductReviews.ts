/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function likeProductReviews () {
  return async (req: Request, res: Response) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user || typeof user.data.email !== 'string') {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    if (typeof id !== 'string') {
      return res.status(400).json({ error: 'Wrong Params' })
    }

    try {
      const result = await db.reviewsCollection.update(
        { _id: id, likedBy: { $ne: user.data.email } },
        {
          $inc: { likesCount: 1 },
          $addToSet: { likedBy: user.data.email }
        }
      )

      if (result.modified === 1) {
        return res.json(result)
      }

      const review = await db.reviewsCollection.findOne({ _id: id })
      if (review == null) {
        return res.status(404).json({ error: 'Not found' })
      }

      return res.status(403).json({ error: 'Already liked' })
    } catch (err) {
      return res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
