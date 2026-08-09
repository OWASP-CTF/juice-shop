/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'
import { AddressModel } from '../models/address'

import * as utils from '../lib/utils'

export const getRecycleItem = () => async (req: Request, res: Response) => {
  // The id was run through JSON.parse and handed to the query builder, so a caller could
  // supply an array or an object where a scalar was expected and widen the selector. It is
  // read as a plain integer, and the row is scoped to the caller so naming somebody else's
  // recycle request returns nothing rather than their address.
  const id = Number.parseInt(req.params.id, 10)
  if (!Number.isSafeInteger(id) || id < 1) {
    res.status(400).json({ error: 'Invalid recycle item id.' })
    return
  }
  try {
    const recycle = await RecycleModel.findAll({ where: { id, UserId: req.body.UserId } })
    res.send(utils.queryResultToJson(recycle))
  } catch {
    res.status(500).send('Error fetching recycled items. Please try again')
  }
}

// A recycle request names the address the collection goes to. Without this the address can
// be one belonging to somebody else.
export const prepareRecycleItem = () => async (req: Request, res: Response, next: NextFunction) => {
  const addressId = Number(req.body.AddressId)
  const userId = Number(req.body.UserId)
  if (!Number.isSafeInteger(addressId) || !Number.isSafeInteger(userId)) {
    res.status(400).json({ error: 'A valid address is required.' })
    return
  }
  try {
    const address = await AddressModel.findOne({ where: { id: addressId, UserId: userId } })
    if (!address) {
      res.status(403).json({ error: 'Address does not belong to the authenticated user.' })
      return
    }
    req.body.AddressId = addressId
    req.body.UserId = userId
    next()
  } catch (error) {
    next(error)
  }
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}

// Listing recycle requests is a legitimate thing for a customer to do; listing everybody's
// was the problem. The collection is scoped to the caller instead of being refused outright.
export const getRecycleItems = () => async (req: Request, res: Response) => {
  try {
    const recycleItems = await RecycleModel.findAll({ where: { UserId: req.body.UserId } })
    res.send(utils.queryResultToJson(recycleItems))
  } catch {
    res.status(500).send('Error fetching recycled items. Please try again')
  }
}
