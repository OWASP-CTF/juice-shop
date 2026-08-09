/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export const getRecycleItem = () => (req: Request, res: Response) => {
  // The id was run through JSON.parse and handed to the query builder, so a caller could
  // supply an array or an object where a scalar was expected and widen the selector
  // instead of naming one row. It is read as a plain integer.
  const id = Number.parseInt(req.params.id, 10)
  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).send(utils.queryResultToJson({ err: 'Invalid recycle id.' }))
  }
  // A recycle record names the customer and the address it is collected from, so it is
  // returned to the customer it belongs to and to nobody else. It used to come back to
  // anyone who could count.
  const requester = security.authenticatedUsers.from(req)
  if (requester?.data?.id === undefined) {
    return res.status(401).send(utils.queryResultToJson({ err: 'Unauthorized' }))
  }
  const where: { id: number, UserId?: number } = { id }
  if (requester.data.role !== security.roles.admin) {
    where.UserId = requester.data.id
  }
  RecycleModel.findAll({ where }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

// Listing recycles used to answer 'this endpoint is not supported' for everyone, which
// withdrew the feature rather than scoping it. Customers get their own records back; the
// unscoped list that disclosed every customer's collection address is what is gone.
export const getRecycleItems = () => (req: Request, res: Response) => {
  const requester = security.authenticatedUsers.from(req)
  if (requester?.data?.id === undefined) {
    return res.status(401).send(utils.queryResultToJson({ err: 'Unauthorized' }))
  }
  const where = requester.data.role === security.roles.admin ? {} : { UserId: requester.data.id }
  RecycleModel.findAll({ where }).then((Recycles) => {
    return res.send(utils.queryResultToJson(Recycles))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}
