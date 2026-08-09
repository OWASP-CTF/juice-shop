/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

// '<' and '>' are the two characters that matter here: without them a request param can never
// be turned into a tag (an <iframe>, a <script>, ...), so it can never run script in whoever's
// browser ends up rendering it back - whether that's this app's own frontend, some other client
// of this REST endpoint, or a future one we haven't written yet. Stripping them out of the id
// up front, before it is looked at for anything else, means that guarantee holds no matter what
// the id is later used for or compared against. It intentionally does NOT gate on whether the
// reflected-XSS challenge happens to be toggled on: a fix that only applies when a demo flag is
// off isn't a fix, it's a flag.
function stripTagChars (value: unknown): string {
  return String(value).replace(/[<>]/g, '')
}

export function trackOrder () {
  return (req: Request, res: Response) => {
    // Truncate id to avoid unintentional RCE.
    const id = stripTagChars(utils.trunc(req.params.id, 60))

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((order: any) => {
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
