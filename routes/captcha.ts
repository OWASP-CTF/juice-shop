/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = eval(expression).toString() // eslint-disable-line no-eval

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    // Only the expression and its id may be sent to the client. The solution
    // ("answer") must stay server-side (already persisted above) so that it
    // cannot be read straight out of the API response and used to script
    // past the CAPTCHA without ever solving it.
    res.json({ captchaId, captcha: expression })
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const requestedId = Number(req.body.captchaId)
    const captcha = Number.isInteger(requestedId) ? await CaptchaModel.findOne({ where: { captchaId: requestedId } }) : null
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      // One puzzle buys one submission. Leaving the row in place would let a single correct
      // answer be replayed indefinitely, which turns the whole check into a formality.
      await captcha.destroy()
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
