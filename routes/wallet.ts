/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'
import * as security from '../lib/insecurity'

export function getWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.id) return res.status(401).json({ status: 'error' })
    const wallet = await WalletModel.findOne({ where: { UserId: user.data.id } })
    if (wallet != null) {
      res.status(200).json({ status: 'success', data: wallet.balance })
    } else {
      res.status(404).json({ status: 'error' })
    }
  }
}

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.id) return res.status(401).json({ status: 'error' })
    const cardId = req.body.paymentId
    const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: user.data.id } }) : null
    if (card != null) {
      try {
        await WalletModel.increment({ balance: req.body.balance }, { where: { UserId: user.data.id } })
        res.status(200).json({ status: 'success', data: req.body.balance })
      } catch {
        res.status(404).json({ status: 'error' })
      }
    } else {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
    }
  }
}
