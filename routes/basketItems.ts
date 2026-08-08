/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { BasketModel } from '../models/basket'
import { QuantityModel } from '../models/quantity'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const result = utils.parseJsonCustom((req as RequestWithRawBody).rawBody)
    const productIds = []
    const basketIds = []
    const quantities = []

    for (let i = 0; i < result.length; i++) {
      if (result[i].key === 'ProductId') {
        productIds.push(result[i].value)
      } else if (result[i].key === 'BasketId') {
        basketIds.push(result[i].value)
      } else if (result[i].key === 'quantity') {
        quantities.push(result[i].value)
      }
    }

    const user = security.authenticatedUsers.from(req)
    const basketId = Number(basketIds[basketIds.length - 1])
    const productId = Number(productIds[productIds.length - 1])
    const quantity = Number(quantities[quantities.length - 1])
    if (!user) {
      res.status(401).json({ error: 'Unauthorized' })
    } else if (!Number.isInteger(basketId) || !Number.isInteger(productId) || !Number.isInteger(quantity) || quantity < 1) {
      res.status(400).json({ error: 'Invalid basket item' })
    } else {
      const basket = await BasketModel.findOne({ where: { id: basketId, UserId: user.data.id } })
      if (!basket) {
        res.status(403).json({ error: 'Invalid BasketId' })
        return
      }
      const basketItem = {
        ProductId: productId,
        BasketId: basketId,
        quantity
      }
      const basketItemInstance = BasketItemModel.build(basketItem)
      try {
        const addedBasketItem = await basketItemInstance.save()
        res.json({ status: 'success', data: addedBasketItem })
      } catch (error) {
        next(error)
      }
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void quantityCheck(req, res, next, req.body.ProductId, req.body.quantity).catch((error: Error) => {
      next(error)
    })
  }
}
export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      const user = security.authenticatedUsers.from(req)
      if (!user) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      const basket = item ? await BasketModel.findOne({ where: { id: item.BasketId, UserId: user.data.id } }) : null
      if (!basket) {
        res.status(403).json({ error: 'Not allowed' })
        return
      }
      if (req.body.quantity !== undefined) {
        if (item == null) {
          throw new Error('No such item found!')
        }
        void quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const productId = Number(id)
  const requestedQuantity = Number(quantity)
  if (!Number.isInteger(productId) || productId < 1 || !Number.isInteger(requestedQuantity) || requestedQuantity < 1) {
    res.status(400).json({ error: 'Invalid quantity' })
    return
  }

  const product = await QuantityModel.findOne({ where: { ProductId: productId } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= requestedQuantity) || security.isDeluxe(req)) {
    if (product.quantity >= requestedQuantity) { // enough in stock?
      req.body.quantity = requestedQuantity
      next()
    } else {
      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
}
