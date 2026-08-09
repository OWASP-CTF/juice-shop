/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

export function trackOrder () {
  return (req: Request, res: Response) => {
    // Restrict the order id to harmless characters so it can never be reflected as markup
    const id = String(req.params.id).replace(/[^\w-]+/g, '')

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    /* One order id names one order. Asking the collection for a set and returning whatever comes
       back lets a lookup that matched more than the order asked for hand all of them over; taking
       a single document means the reply cannot carry another customer's order however the
       selector is built. */
    db.ordersCollection.findOne({ orderId: id }).then((order: any) => {
      const result = utils.queryResultToJson(order ? [order] : [])
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
