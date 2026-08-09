/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'

/* Answering with an empty object for unknown addresses and with a question for known ones
   turns this endpoint into an account existence oracle, which is exactly what an attacker
   needs before starting to guess answers. Unknown addresses therefore get a question too,
   picked deterministically from the same catalogue so that repeated requests stay
   consistent and indistinguishable from a real account. */
async function decoyQuestionFor (email: string) {
  const questions = await SecurityQuestionModel.findAll({ order: [['id', 'ASC']] })
  if (questions.length === 0) {
    return null
  }
  const digest = crypto.createHash('sha256').update(email).digest()
  return questions[digest.readUInt32BE(0) % questions.length]
}

export function securityQuestion () {
  return async ({ query }: Request, res: Response, next: NextFunction) => {
    const email = query.email?.toString() ?? ''
    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if (answer != null) {
        const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
        res.json({ question })
      } else {
        res.json({ question: await decoyQuestionFor(email) })
      }
    } catch (error) {
      next(error)
    }
  }
}
