/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as models from '../models/index'

export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    const rawCriteria = typeof req.query.q === 'string' && req.query.q !== 'undefined' ? req.query.q : ''
    const criteria = rawCriteria.substring(0, 200)
    models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name', {
      replacements: { criteria: `%${criteria}%` }
    })
      .then(([products]: any) => {
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: Error) => {
        next(error)
      })
  }
}
