/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'

export function getWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
    if (wallet != null) {
      res.status(200).json({ status: 'success', data: wallet.balance })
    } else {
      res.status(404).json({ status: 'error' })
    }
  }
}

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const cardId = req.body.paymentId
    // The credited amount was taken from the request unchecked, so a caller could name any
    // figure - or a negative one, which increment applies as a debit against the wallet.
    const amount = Number(req.body.balance)
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1000) {
      res.status(400).json({ status: 'error', message: 'Invalid amount.' })
      return
    }
    const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
    if (card != null) {
      try {
        await WalletModel.increment({ balance: amount }, { where: { UserId: req.body.UserId } })
        res.status(200).json({ status: 'success', data: amount })
      } catch {
        res.status(404).json({ status: 'error' })
      }
    } else {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
    }
  }
}
