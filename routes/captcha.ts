/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

export const operators = ['*', '+', '-']

export function generateCaptchaTerms () {
  const firstTerm = crypto.randomInt(1, 11)
  const secondTerm = crypto.randomInt(1, 11)
  const thirdTerm = crypto.randomInt(1, 11)

  const firstOperator = operators[crypto.randomInt(0, 3)]
  const secondOperator = operators[crypto.randomInt(0, 3)]

  return { firstTerm, secondTerm, thirdTerm, firstOperator, secondOperator }
}

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const { firstTerm, secondTerm, thirdTerm, firstOperator, secondOperator } = generateCaptchaTerms()

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = eval(expression).toString() // eslint-disable-line no-eval

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
