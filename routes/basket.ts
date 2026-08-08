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

      if (
        !user ||
        !user.bid ||
        !id ||
        id === 'undefined' ||
        id === 'null' ||
        id === 'NaN' ||
        user.bid !== parseInt(id, 10)
      ) {
        res.status(403).json({
          status: 'error',
          message: 'Access denied.'
        })
        return
      }

      const basket = await BasketModel.findOne({
        where: {
          id: user.bid
        },
        include: [{
          model: ProductModel,
          paranoid: false,
          as: 'Products'
        }]
      })

      if (basket?.Products != null && basket.Products.length > 0) {
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
