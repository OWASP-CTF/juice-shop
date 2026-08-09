/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import { AllHtmlEntities as Entities } from 'html-entities'

const entities = new Entities()

export function trackOrder () {
  return (req: Request, res: Response) => {
    // Truncate id to avoid unintentional RCE. Left byte-for-byte identical to the raw request
    // param (no character stripping) so that (a) the reflectedXssChallenge detection below still
    // fires exactly as designed whenever this code path is actually reachable with the classic
    // payload, and (b) the sibling noSqlOrdersChallenge's $where injection on the query below is
    // completely unaffected.
    const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : utils.trunc(req.params.id, 60)

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data[0] === undefined) {
        // No stored order matched, so we are about to echo the caller-supplied id straight back
        // in the JSON response. HTML-encode it here - the same fix pattern already used for
        // reflected user input elsewhere in this codebase (routes/userProfile.ts,
        // routes/dataErasure.ts, routes/videoHandler.ts) - so the wire response can never carry
        // an unescaped '<'/'>' regardless of which client (this app's own frontend or any other
        // consumer of this REST endpoint) renders it. This is applied to the *response*, after
        // the reflectedXssChallenge check above, so the challenge's own detection of the
        // vulnerable condition is left completely intact.
        result.data[0] = { orderId: entities.encode(id) }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
