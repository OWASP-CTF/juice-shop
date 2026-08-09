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
    const answer = evaluate(firstTerm, firstOperator, secondTerm, secondOperator, thirdTerm).toString()

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

/* Evaluates the generated arithmetic expression without handing it to an interpreter.
   The terms and operators are produced above and are the only accepted inputs. */
function evaluate (firstTerm: number, firstOperator: string, secondTerm: number, secondOperator: string, thirdTerm: number) {
  const apply = (left: number, operator: string, right: number) => {
    switch (operator) {
      case '*': return left * right
      case '-': return left - right
      default: return left + right
    }
  }
  // Keep the precedence a reader of the expression would expect.
  if (firstOperator !== '*' && secondOperator === '*') {
    return apply(firstTerm, firstOperator, secondTerm * thirdTerm)
  }
  return apply(apply(firstTerm, firstOperator, secondTerm), secondOperator, thirdTerm)
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      // A CAPTCHA proves one interaction, so it is consumed on first successful use and
      // cannot be replayed for a second submission.
      await captcha.destroy()
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
