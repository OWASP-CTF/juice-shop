/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'

const orderIdPattern = /^[0-9a-f]{4}-[0-9a-f]{16}$/

export function trackOrder () {
  return (req: Request, res: Response) => {
    const id: unknown = req.params.id
    if (typeof id !== 'string' || !orderIdPattern.test(id)) {
      return res.status(400).json({ error: 'Wrong Param' })
    }

    return db.ordersCollection.findOne({ orderId: id }).then((order: any) => {
      const { UserId: _UserId, ...publicOrder } = order ?? { orderId: id }
      const result = utils.queryResultToJson([publicOrder])
      return res.json(result)
    }, () => {
      return res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
