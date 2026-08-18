/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

/* The generated REST layer updates the row named in the path and takes the caller's word for
   which row that is, so a session was enough to rewrite any address book entry in the shop -
   including the delivery address of an order somebody else is about to place. Reading and
   deleting an address were already scoped to the owner; updating one is gated the same way,
   ahead of the update, and a row that is not the caller's is answered exactly like a row that
   does not exist so the endpoint gives nothing away about other customers' data either. */
export function requireOwnAddress () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const ownAddress = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (ownAddress != null) {
      next()
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function getAddress () {
  return async (req: Request, res: Response) => {
    const addresses = await AddressModel.findAll({ where: { UserId: req.body.UserId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}
