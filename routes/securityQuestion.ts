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
    // No session requirement: a user who has forgotten their password cannot
    // have one. What made this dangerous was guessable security answers, which
    // are no longer shipped; the answer itself is still what gates the reset.
    if (!email) {
      res.sendStatus(400)
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
