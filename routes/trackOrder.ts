/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

/* An order id is a shape the shop issues itself. Anything else is refused rather than repaired,
   so no caller-supplied text reaches the query or the page. */
const ORDER_ID_PATTERN = /^[a-zA-Z0-9-]{1,60}$/

export function trackOrder () {
  return (req: Request, res: Response) => {
    const id = String(req.params.id ?? '')

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })

    if (!ORDER_ID_PATTERN.test(id)) {
      res.status(400).json({ error: 'Invalid order id' })
      return
    }

    /* An order belongs to the customer who placed it. Knowing - or guessing - an order id is not
       the same as being allowed to read the order, and order ids are short and enumerable, so
       tracking is answered only for the caller's own orders. Without this the endpoint hands out
       other customers' addresses and totals to anyone who asks. */
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      res.status(401).json({ error: 'You have to be logged in to track an order' })
      return
    }

    /* Both fields are matched as values. The selector used to be a $where clause - executable
       JavaScript assembled from the id - so an always-true expression returned the whole order
       collection instead of the one order the customer asked about. */
    db.ordersCollection.find({ orderId: id, email: user.data.email.replace(/[aeiou]/gi, '*') }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
