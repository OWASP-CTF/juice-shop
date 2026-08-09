/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { ordersCollection } from '../data/mongodb'

/* Every file the shop legitimately publishes here is an invoice it generated itself, named after
   the order it belongs to. The name is therefore checked against the requester's own orders
   rather than against a list of extensions: an allow-list of file types says nothing about who
   the file belongs to, and it was what let the acquisition memo and the developer's leftovers be
   downloaded by anyone who guessed the name. */
const INVOICE_PATTERN = /^order_[\w-]+\.pdf$/

export function servePublicFiles () {
  return async ({ params, ...req }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file || file.includes('/') || /%00|\0/i.test(file)) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })

    if (!INVOICE_PATTERN.test(file)) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }

    const user = security.authenticatedUsers.from(req as Request)
    if (!user?.data?.email) {
      res.status(401).json({ error: 'You have to be logged in to download an invoice' })
      return
    }

    const orderId = file.substring('order_'.length, file.length - '.pdf'.length)
    const orders = await ordersCollection.find({ orderId, email: user.data.email })
    if (!orders || orders.length === 0) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }

    res.sendFile(path.resolve('ftp/', file))
  }
}
