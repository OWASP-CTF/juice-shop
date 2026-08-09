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
    /* Strip everything that is not a word character or dash. A legitimate order id
       (e.g. 5267-f9cd5882f54c75a3) is unaffected, but an <iframe>/<script> payload in
       the URL no longer survives to be reflected back into the page (A05:2025, CWE-79).
       Doing this unconditionally also removes the previous "challenge enabled" branch
       that deliberately kept the payload intact. */
    const id = String(req.params.id).replace(/[^\w-]+/g, '')

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    /* A plain equality match instead of $where, whose JavaScript body could be broken
       out of with a quote to make the predicate always true and return every order in
       the collection (CWE-943). */
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
