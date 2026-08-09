/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

export const getRecycleItem = () => (req: Request, res: Response) => {
  // The id was run through JSON.parse and handed to the query builder, so a caller could
  // supply an array or an object where a scalar was expected and widen the selector
  // instead of naming one row. It is read as a plain integer.
  const id = Number.parseInt(req.params.id, 10)
  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).send(utils.queryResultToJson({ err: 'Invalid recycle id.' }))
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
