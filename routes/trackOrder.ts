/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

/* An order id is a fixed shape the shop issues itself: two groups of hex digits joined by a
   hyphen. Anything else is not an order id and is refused rather than repaired, so no
   caller-supplied text ever reaches the query or the page. */
const ORDER_ID_PATTERN = /^[a-zA-Z0-9-]{1,60}$/

export function trackOrder () {
  return (req: Request, res: Response) => {
    const id = String(req.params.id ?? '')

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })

    if (!ORDER_ID_PATTERN.test(id)) {
      res.status(400).json({ error: 'Invalid order id' })
      return
    }

    /* The lookup is an equality match on a value. It used to be a $where clause - executable
       JavaScript assembled from the id - so an always-true expression returned the entire order
       collection instead of the one order the customer asked about. */
    db.ordersCollection.find({ orderId: id }).then((order: any) => {
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
