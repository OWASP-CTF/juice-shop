/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

export const getRecycleItem = () => (req: Request, res: Response) => {
  /* Running the path segment through JSON.parse meant the caller decided what *kind* of value
     landed in the where clause, not just which value: an object such as {"$gt":0} became a
     Sequelize operator expression and turned a lookup of one recycling request into a dump of
     everybody's. A recycle id is a row id, so it is read as one and nothing else. */
  const id = Number(req.params.id)
  if (!Number.isInteger(id)) {
    res.status(400).send('Error fetching recycled items. Please try again')
    return
  }
  RecycleModel.findAll({
    where: { id }
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
