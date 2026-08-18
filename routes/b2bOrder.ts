/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// orderLinesData is documented (Swagger) to carry a JSON-encoded string, e.g.
// '{"productId":12,"quantity":10000,"customerReference":["PO0000001.2"],"couponCode":"..."}'
// A prior version of this endpoint fed that untrusted string into a JS "sandbox"
// (node:vm + notevil) and executed it as code. A vm context is not a real security
// boundary and notevil-style sandboxes are routinely bypassable, so this allowed
// remote code execution and denial-of-service (infinite loops / ReDoS) via a single
// request. orderLinesData must only ever be treated as data: it is now deserialized
// with JSON.parse - which can only ever produce plain data (objects/arrays/strings/
// numbers/booleans/null), never executable code - and is never evaluated. A generous
// but finite length cap is enforced before parsing as defense in depth against
// oversized-payload abuse.
const MAX_ORDER_LINES_DATA_LENGTH = 100_000

export function b2bOrder () {
  // `next` is accepted but unused: this handler now resolves every path itself (there is no
  // interpreter left to throw), and keeping the standard three-argument Express signature is
  // what existing callers and the route's own tests type-check against.
  return ({ body }: Request, res: Response, next?: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      if (typeof orderLinesData !== 'string' || orderLinesData.length > MAX_ORDER_LINES_DATA_LENGTH) {
        res.status(400)
        res.json({ error: 'Invalid orderLinesData' })
        return
      }
      try {
        if (orderLinesData.length > 0) {
          JSON.parse(orderLinesData)
        }
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch {
        // Malformed input is rejected outright and never reaches an interpreter -
        // there is no code path left here that can execute attacker-controlled data.
        res.status(400)
        res.json({ error: 'Invalid orderLinesData' })
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
