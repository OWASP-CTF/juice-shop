/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'
import { ProductModel } from '../models/product'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
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

    // parseJsonCustom is a streaming parser: it keeps EVERY occurrence of a duplicated key.
    // The guard used to read basketIds[0] while the insert below used the last entry, so a
    // body carrying two BasketId values was authorised against one basket and written into
    // another. Check and write now agree on this single value, and a body whose duplicates
    // disagree is rejected instead of being resolved in the sender's favour.
    const requestedBasketId = basketIds.length > 0 ? basketIds[basketIds.length - 1] : undefined
    let conflictingBasketIds = false
    for (let i = 0; i < basketIds.length; i++) {
      if (String(basketIds[i]) !== String(requestedBasketId)) {
        conflictingBasketIds = true
      }
    }

    if (conflictingBasketIds) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else if (user && requestedBasketId && requestedBasketId !== 'undefined' && Number(user.bid) != Number(requestedBasketId)) { // eslint-disable-line eqeqeq
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: productIds[productIds.length - 1],
        // The session's own basket wins over anything the body names.
        BasketId: user?.bid ?? requestedBasketId,
        quantity: quantities[quantities.length - 1]
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketItem.BasketId && basketItem.BasketId !== 'undefined' && user.bid != basketItem.BasketId }) // eslint-disable-line eqeqeq

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

      // The path id was unscoped, so any authenticated user could address another customer's
      // line item and have the finale update it. A line item is only updatable from inside
      // the basket it belongs to.
      if (item != null && (!user?.bid || Number(item.BasketId) !== Number(user.bid))) {
        res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
        return
      }
      // Moving a line item to a different basket is not an update this endpoint offers, so a
      // BasketId in the body is pinned to the item's own basket before the finale writes it.
      if (item != null && req.body.BasketId !== undefined) {
        req.body.BasketId = item.BasketId
      }

      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      if (req.body.quantity) {
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
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // A quantity below one is not an order. Left unchecked it multiplies through to a
  // negative line total, and enough of it turns the whole order total negative.
  const orderedQuantity = Number(quantity)
  if (!Number.isInteger(orderedQuantity) || orderedQuantity < 1) {
    res.status(400).json({ error: res.__('Invalid quantity.') })
    return
  }

  // QuantityModel is not paranoid but ProductModel is, so a discontinued product keeps
  // its quantity row and would otherwise still pass the stock check below.
  const orderedProduct = await ProductModel.findByPk(id)
  if (orderedProduct == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      next()
    } else {
      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
}
