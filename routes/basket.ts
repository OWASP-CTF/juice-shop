/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      const user = security.authenticatedUsers.from(req)

      if (user == null || user.bid == null) {
        res.status(401).json({
          error: 'Unauthorized'
        })
        return
      }

      const requestedBasketId = Number(id)
      const userBasketId = Number(user.bid)

      if (
        !Number.isInteger(requestedBasketId) ||
        requestedBasketId <= 0
      ) {
        res.status(400).json({
          error: 'Invalid BasketId'
        })
        return
      }

      /*
       * A user may only retrieve their own basket.
       */
      if (requestedBasketId !== userBasketId) {
        res.status(403).json({
          error: 'Access denied'
        })
        return
      }

      const basket = await BasketModel.findOne({
        where: {
          id: userBasketId
        },
        include: [{
          model: ProductModel,
          paranoid: false,
          as: 'Products'
        }]
      })

      if (basket == null) {
        res.status(404).json({
          error: 'Basket not found'
        })
        return
      }

      if (
        basket.Products != null &&
        basket.Products.length > 0
      ) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
