/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

// This app mints an order id as a four-character hash fragment, a hyphen, and sixteen hex
// characters (see routes/order.ts and data/datacreator.ts), so word characters and hyphens are
// the *entire* legitimate alphabet for this parameter. Normalising the incoming value to that
// alphabet is an allowlist rather than a blacklist, which is what makes it safe to reason about:
// rather than trying to enumerate the dangerous characters and inevitably missing one, it keeps
// only the characters an order id is ever made of and drops everything else. That single rule
// covers both ways this value has been getting away from us - '<' and '>' go, so the id can
// never become a tag (an <iframe>, a <script>, ...) in any client that renders it back, and
// quotes, backticks and semicolons go too, so it can never break out of the string literal it
// is compared against below.
//
// It runs unconditionally and before the id is used for anything: a parameter that is only
// validated while some demo flag happens to be off is not really validated at all.
function normalizeOrderId (value: unknown): string {
  return utils.trunc(String(value), 60).replace(/[^\w-]+/g, '')
}

export function trackOrder () {
  return (req: Request, res: Response) => {
    const id = normalizeOrderId(req.params.id)

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    // Match on a plain equality selector instead of interpolating the id into a `$where`
    // expression. `$where` hands its string to the query engine to *evaluate as JavaScript*, so
    // building it by string concatenation let a request parameter run as code on the server -
    // the original "truncate id to avoid unintentional RCE" comment was an admission of exactly
    // that, and a length cap is no defence against it. A selector object is data: the engine
    // compares the id, it never executes it. This also stops a malformed id from throwing out of
    // the query and returning a stack trace to the caller.
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
