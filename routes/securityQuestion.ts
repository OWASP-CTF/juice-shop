/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'
import * as security from '../lib/insecurity'

export function securityQuestion () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const email = req.query.email?.toString()
    const authenticatedUser = security.authenticatedUsers.from(req)
    if (!authenticatedUser?.data?.email || authenticatedUser.data.email !== email) {
      res.sendStatus(403)
      return
    }
    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email: email?.toString() }
        }]
      })
      if (answer != null) {
        const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
        res.json({ question })
      } else {
        res.json({})
      }
    } catch (error) {
      next(error)
    }
  }
}
