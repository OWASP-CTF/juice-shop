/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { AddressModel } from '../models/address'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

export const requireOwnedRecycleAddress = () => async (req: Request, res: Response, next: NextFunction) => {
  const addressId = Number(req.body.AddressId)
  if (!Number.isInteger(addressId)) {
    return res.status(400).json({ error: 'A valid address is required.' })
  }
  const address = await AddressModel.findOne({ where: { id: addressId, UserId: req.body.UserId } })
  if (address == null) {
    return res.status(403).json({ error: 'The selected address is not owned by this account.' })
  }
  req.body.AddressId = addressId
  next()
}

export const listOwnedRecycleItems = () => async (req: Request, res: Response) => {
  const items = await RecycleModel.findAll({ where: { UserId: req.body.UserId } })
  res.send(utils.queryResultToJson(items))
}

export const getOwnedRecycleItem = () => async (req: Request, res: Response) => {
  const itemId = Number(req.params.id)
  if (!Number.isInteger(itemId) || itemId < 1) {
    return res.status(400).json({ error: 'Invalid recycle item id.' })
  }
  const item = await RecycleModel.findOne({ where: { id: itemId, UserId: req.body.UserId } })
  if (item == null) {
    return res.status(404).json({ error: 'Recycle item not found.' })
  }
  res.send(utils.queryResultToJson([item]))
}