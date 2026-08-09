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

// A top-up is a positive amount of currency, bounded by what the wallet form itself allows
// (min 10 / max 1000). Nothing was charged to the card before, so whatever number the body
// carried went straight into the increment below - including a negative one, which drove the
// balance below zero, and a non-numeric one, which reached Sequelize unchecked.
const MAX_TOPUP = 1000

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const requestedBalance = req.body.balance
    const amount = (typeof requestedBalance === 'number' || typeof requestedBalance === 'string') ? Number(requestedBalance) : NaN
    if (!Number.isFinite(amount) || amount <= 0 || amount > MAX_TOPUP) {
      res.status(400).json({ status: 'error', message: 'Invalid amount.' })
      return
    }

    const cardId = req.body.paymentId
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
