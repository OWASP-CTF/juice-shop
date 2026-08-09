/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    const orderLinesData = body.orderLinesData || ''
    // Order line data must only ever be parsed as inert data, never evaluated as code.
    // A "safe eval" sandbox (vm + notevil) is not an effective security boundary - both
    // are documented to be escapable - so the only real fix is to not execute
    // attacker-controlled input at all.
    if (orderLinesData) {
      try {
        JSON.parse(orderLinesData)
      } catch (err) {
        // Detection stays wired up on the same conditions as upstream. Parsing inert JSON
        // can neither spin forever nor exhaust the event loop, so neither can now fire.
        challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return utils.getErrorMessage(err).match(/Script execution timed out.*/) != null })
        challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
        res.status(400)
        next(new Error('Invalid order line data'))
        return
      }
    }
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
