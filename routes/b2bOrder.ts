/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

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
