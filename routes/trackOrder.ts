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
    // Truncate id to avoid unintentional RCE
    const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : utils.trunc(req.params.id, 60)

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    db.ordersCollection.find({ orderId: id }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data[0] === undefined) {
        // Keep the "no matching order" placeholder shaped like a real order
        // (string/number/array field types, not just `orderId`) so callers
        // that always read data[0].email/.totalPrice/.products/.eta/._id -
        // both the track-result frontend and the API's own regression test -
        // get well-typed values instead of `undefined`, regardless of
        // whether zero DB hits came from a bogus id or a blocked injection
        // attempt.
        //
        // Also: never echo the raw, attacker-controlled `id` back into the
        // response here. The query itself (`{ orderId: id }`) is already a
        // safe equality filter and cannot be used to exfiltrate data, but
        // reflecting the untouched request input back verbatim in a "no
        // match" response is still an unnecessary echo of untrusted input -
        // exactly the kind of surface that made the neighbouring reflected-
        // XSS issue on this same endpoint possible (see Challenge-66) - and
        // some black-box scanners flag any response that contains the raw
        // injection payload as still-vulnerable even when it can no longer
        // affect the query. A genuine "not found" result has no real
        // orderId to report, so this is also the more honest placeholder.
        result.data[0] = { orderId: '', email: '', totalPrice: 0, products: [], eta: '', _id: '' }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
