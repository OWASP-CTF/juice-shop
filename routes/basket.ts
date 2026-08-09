/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      // The basket id travels in the path and the client can edit it, so a session may
      // only read its own basket. The refusal is issued before anything else so a caller
      // never reaches somebody else's basket contents. A session that cannot be resolved
      // at all is left to the authorisation middleware rather than refused here, so a
      // valid token that predates this process still behaves as it did before.
      const requester = security.authenticatedUsers.from(req)
      if (requester != null && basket != null) {
        const ownsByUserId = requester.data?.id === basket.UserId
        const ownsByBasketId = requester.bid !== undefined && Number(requester.bid) === parseInt(id, 10)
        if (!ownsByUserId && !ownsByBasketId) {
          res.status(403).json({ error: 'Malicious activity detected' })
          return
        }
      }
      /* jshint eqeqeq:false */
      challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
        const user = security.authenticatedUsers.from(req)
        return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user?.bid != parseInt(id, 10) // eslint-disable-line eqeqeq
      })
      if (((basket?.Products) != null) && basket.Products.length > 0) {
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
