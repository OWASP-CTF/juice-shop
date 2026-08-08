/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'

export function applyCoupon () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      const userId = security.authenticatedUsers.from(req)?.data?.id
      if (typeof userId !== 'number' || !Number.isSafeInteger(userId) || userId <= 0) {
        res.status(401).json({ status: 'error', message: 'Invalid authentication data' })
        return
      }

      let coupon: string | undefined | null = req.params.coupon ? decodeURIComponent(req.params.coupon) : undefined
      const discount = security.discountFromCoupon(coupon)
      coupon = discount ? coupon : null

      const basket = await BasketModel.findByPk(id)
      if (!basket) {
        next(new Error(`Basket with id=${id} does not exist.`))
        return
      }
      if (basket.UserId !== userId) {
        res.status(403).json({ status: 'error', message: 'Basket does not belong to the authenticated user' })
        return
      }

      await basket.update({ coupon: coupon?.toString() })
      if (discount) {
        return res.json({ discount })
      } else {
        return res.status(404).send('Invalid coupon.')
      }
    } catch (error) {
      next(error)
    }
  }
}
