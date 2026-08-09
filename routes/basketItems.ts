/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { ProductModel } from '../models/product'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

/* A basket line always stands for a whole number of items that are actually being bought. A
   negative or fractional amount is not a quantity, it is a way to subtract money from the order
   total, so it is rejected at the edge instead of being carried into the price calculation. */
const isOrderableQuantity = (quantity: unknown) => {
  const value = Number(quantity)
  return Number.isInteger(value) && value > 0
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
    if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) { // eslint-disable-line eqeqeq
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: productIds[productIds.length - 1],
        BasketId: basketIds[basketIds.length - 1],
        quantity: quantities[quantities.length - 1]
      }

      if (!isOrderableQuantity(basketItem.quantity)) {
        res.status(400).json({ error: 'Quantity must be a whole number greater than zero.' })
        return
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketItem.BasketId && basketItem.BasketId !== 'undefined' && user.bid != basketItem.BasketId }) // eslint-disable-line eqeqeq

      /* Only a product that is actually on sale can be put into a basket. Products taken out of
         the assortment are merely flagged as deleted, so without this check a discontinued item
         could still be added - and ordered - straight through the API. */
      const onSale = basketItem.ProductId !== undefined ? await ProductModel.findOne({ where: { id: basketItem.ProductId } }) : null
      if (onSale == null) {
        res.status(400).json({ error: 'This product is no longer available.' })
        return
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
      if (item == null) {
        res.status(404).json({ error: 'No such item found!' })
        return
      }
      /* A basket line may only be changed by the owner of the basket it sits in, and it can never
         be reassigned to a different basket. Both checks happen before anything else so that a
         cross-basket write is refused rather than merely observed. */
      if (user?.bid === undefined || Number(item.BasketId) !== Number(user.bid)) {
        res.status(403).json({ error: 'Malicious activity detected.' })
        return
      }
      if (req.body.BasketId !== undefined && Number(req.body.BasketId) !== Number(user.bid)) {
        res.status(403).json({ error: 'Malicious activity detected.' })
        return
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      if (req.body.quantity) {
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
  if (!isOrderableQuantity(quantity)) {
    res.status(400).json({ error: 'Quantity must be a whole number greater than zero.' })
    return
  }
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
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
