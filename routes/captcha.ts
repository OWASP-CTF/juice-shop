/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

type CaptchaOperator = '*' | '+' | '-'

const applyOperator = (left: number, operator: CaptchaOperator, right: number) => {
  switch (operator) {
    case '*': return left * right
    case '+': return left + right
    case '-': return left - right
  }
}

const solveExpression = (firstTerm: number, firstOperator: CaptchaOperator, secondTerm: number, secondOperator: CaptchaOperator, thirdTerm: number) => {
  if (firstOperator === '*') {
    return applyOperator(firstTerm * secondTerm, secondOperator, thirdTerm)
  }
  if (secondOperator === '*') {
    return applyOperator(firstTerm, firstOperator, secondTerm * thirdTerm)
  }
  return applyOperator(applyOperator(firstTerm, firstOperator, secondTerm), secondOperator, thirdTerm)
}

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators: CaptchaOperator[] = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = solveExpression(firstTerm, firstOperator, secondTerm, secondOperator, thirdTerm).toString()

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    /* The answer is server-side verification data. Returning it allowed a
       client to solve every generated CAPTCHA without human interaction. */
    res.json({ captchaId, captcha: expression })
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      /* A captcha was never consumed, so one solved challenge could be replayed
         indefinitely to submit in bulk. Each captcha is now single-use. */
      await CaptchaModel.destroy({ where: { captchaId: req.body.captchaId } })
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
