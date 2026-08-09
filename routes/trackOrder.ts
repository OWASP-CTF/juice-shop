/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'

export function trackOrder () {
  return (req: Request, res: Response) => {
    const id = String(req.params.id).replace(/[^\w-]+/g, '')

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })

    const customer = security.authenticatedUsers.from(req)
    if (!customer?.data?.email) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    // Orders are stored against the same masked address the chatbot matches on, so an order is
    // looked up by its identifier and by whose it is, never by identifier alone.
    const owner = customer.data.email.replace(/[aeiou]/gi, '*')

    db.ordersCollection.find({ orderId: id, email: owner }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data.length === 0) {
        res.status(404).json({ error: 'No order of yours matches that identifier.' })
        return
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
