/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { AddressModel } from '../models/address'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

export const prepareRecycleItem = () => async (req: Request, res: Response, next: NextFunction) => {
  const addressId = Number(req.body.AddressId)
  const userId = Number(req.body.UserId)
  if (!Number.isInteger(addressId) || !Number.isInteger(userId)) {
    res.status(400).json({ error: 'A valid address is required.' })
    return
  }

  const address = await AddressModel.findOne({ where: { id: addressId, UserId: userId } })
  if (!address) {
    res.status(403).json({ error: 'Address does not belong to the authenticated user.' })
    return
  }

  req.body.AddressId = addressId
  req.body.UserId = userId
  next()
}

export const getRecycleItems = () => async (req: Request, res: Response) => {
  const recycleItems = await RecycleModel.findAll({ where: { UserId: req.body.UserId } })
  res.send(utils.queryResultToJson(recycleItems))
}

export const getRecycleItem = () => async (req: Request, res: Response) => {
  const id = Number(req.params.id)
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'Invalid recycle item id.' })
    return
  }

  const recycleItem = await RecycleModel.findOne({ where: { id, UserId: req.body.UserId } })
  if (!recycleItem) {
    res.status(404).json({ error: 'Recycle item not found.' })
    return
  }
  res.send(utils.queryResultToJson([recycleItem]))
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
