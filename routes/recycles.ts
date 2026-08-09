/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

export const getRecycleItem = () => (req: Request, res: Response) => {
  // JSON.parse turned the path segment into whatever the caller wanted, so
  // "[1,2,3]" became an IN clause and this unauthenticated route enumerated
  // other users' recycle records in one request.
  const id = Number(req.params.id)
  if (!Number.isInteger(id)) {
    return res.status(400).send('Error fetching recycled items. Please try again')
  }
  RecycleModel.findAll({
    where: {
      id
    }
  }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
