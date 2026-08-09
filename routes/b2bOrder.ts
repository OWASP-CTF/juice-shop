/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

const MAX_ORDER_LINES_LENGTH = 100000

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    const orderLinesData = body.orderLinesData
    if (orderLinesData !== undefined && orderLinesData !== null && orderLinesData !== '') {
      if (typeof orderLinesData === 'string') {
        if (orderLinesData.length > MAX_ORDER_LINES_LENGTH) {
          res.status(413)
          next(new Error('Order lines data exceeds the maximum accepted size'))
          return
        }
        try {
          JSON.parse(orderLinesData)
        } catch {
          res.status(400)
          next(new Error('Order lines data must be valid JSON'))
          return
        }
      } else if (typeof orderLinesData !== 'object') {
        res.status(400)
        next(new Error('Order lines data must be valid JSON'))
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
