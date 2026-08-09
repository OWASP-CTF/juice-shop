/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

export function orderHistory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      // Orders are stored against the address with its vowels starred out, and that is not an
      // identity: every address differing only in its vowels masks to the same string, so this
      // lookup hands one customer another customer's order history. placeOrder() derives each
      // order number from a hash of the owning address, so the rows are additionally confined
      // to the ones this account actually placed.
      const updatedEmail = email.replace(/[aeiou]/gi, '*')
      const orderPrefix = security.hash(email).slice(0, 4) + '-'
      const orders = await ordersCollection.find({ email: updatedEmail })
      res.status(200).json({ status: 'success', data: orders.filter((order: { orderId?: string }) => order.orderId?.startsWith(orderPrefix)) })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

export function allOrders () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const order = await ordersCollection.find()
    res.status(200).json({ status: 'success', data: order.reverse() })
  }
}

export function toggleDeliveryStatus () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const deliveryStatus = !req.body.deliveryStatus
    const eta = deliveryStatus ? '0' : '1'
    await ordersCollection.update({ _id: req.params.id }, { $set: { delivered: deliveryStatus, eta } })
    res.status(200).json({ status: 'success' })
  }
}
