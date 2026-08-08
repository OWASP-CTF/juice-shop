/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (body.orderLinesData !== undefined) {
      try {
        parseOrderLinesData(body.orderLinesData)
      } catch {
        res.status(400).json({ error: 'orderLinesData must contain a valid JSON object or array' })
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

function parseOrderLinesData (orderLinesData: unknown) {
  if (typeof orderLinesData !== 'string') {
    throw new TypeError('orderLinesData must be a string')
  }

  const parsedOrderLines = JSON.parse(orderLinesData)
  if (parsedOrderLines === null || typeof parsedOrderLines !== 'object') {
    throw new TypeError('orderLinesData must contain an object or array')
  }
}
