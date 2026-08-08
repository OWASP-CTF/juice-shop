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
    const balance = Number(req.body.balance)
    const parsedCardId = Number(cardId)
    const card = cardId && Number.isInteger(parsedCardId)
      ? await CardModel.findOne({ where: { id: parsedCardId, UserId: req.body.UserId } })
      : null
    if (card != null && Number.isFinite(balance) && balance > 0 && balance <= 100000) {
      try {
        await WalletModel.increment({ balance }, { where: { UserId: req.body.UserId } })
        res.status(200).json({ status: 'success', data: balance })
      } catch {
        res.status(404).json({ status: 'error' })
      }
    } else {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
    }
  }
}
