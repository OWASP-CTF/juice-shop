/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }
    const id = req.body.id
    const message = req.body.message
    if (typeof id !== 'string' || typeof message !== 'string') {
      res.status(400).json({ error: 'Invalid review update payload' })
      return
    }
    // Only the author of a review may edit it, and only ever a single document.
    db.reviewsCollection.update(
      { _id: id, author: user.data.email },
      { $set: { message } },
      { multi: false }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
