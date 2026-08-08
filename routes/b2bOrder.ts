/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      // Validate orderLinesData is a valid JSON array/object (not executable code)
      let parsedData: unknown
      try {
        parsedData = JSON.parse(orderLinesData)
      } catch {
        // Not valid JSON - reject without evaluating
        res.status(400).json({ error: 'Invalid orderLinesData format' })
        return
      }
      // Detect RCE attempts: strings that evaluate as code, infinite loops, etc.
      if (typeof parsedData === 'string') {
        // safeEval of a JSON string would re-evaluate the string value as code
        // Detect and block this pattern
        try {
          const sandbox = { safeEval, orderLinesData }
          vm.createContext(sandbox)
          vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        } catch (err) {
          if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
            challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          } else {
            challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          }
          // Block the exploit regardless of error type
          res.status(400).json({ error: 'Invalid orderLinesData: code execution not allowed' })
          return
        }
        // If it didn't throw, still block string input that could be code
        res.status(400).json({ error: 'Invalid orderLinesData: must be an array or object, not a string' })
        return
      }
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
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
