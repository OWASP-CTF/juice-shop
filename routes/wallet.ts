/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'

/* A single top-up is capped, so a typo or a tampered field cannot mint an unbounded balance. */
const MAX_TOP_UP = 1000

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
    const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
    if (card != null) {
      /* The amount was taken from the request and credited verbatim: the card was looked up but
         never charged, so any figure the caller typed became real money, and a negative one drained
         the balance instead. The amount has to be a sane, bounded, positive number of cents before
         anything is credited. Topping up with a real card behaves exactly as before. */
      const amount = Number(req.body.balance)
      if (!Number.isFinite(amount) || amount <= 0 || Math.round(amount * 100) !== amount * 100 || amount > MAX_TOP_UP) {
        res.status(400).json({ status: 'error', message: 'Invalid top-up amount.' })
        return
      }
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
