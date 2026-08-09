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
      let coupon: string | undefined | null = req.params.coupon ? decodeURIComponent(req.params.coupon) : undefined
      const discount = security.discountFromCoupon(coupon)
      coupon = discount ? coupon : null

      const basket = await BasketModel.findByPk(id)
      if (!basket) {
        next(new Error(`Basket with id=${id} does not exist.`))
        return
      }

      // The basket id comes from the path. Without this the endpoint writes a coupon onto
      // whichever basket is named, not the one belonging to the caller.
      const customer = security.authenticatedUsers.from(req)
      if (!customer?.data?.id || basket.UserId !== customer.data.id) {
        res.status(403).json({ error: 'Malicious activity detected.' })
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
