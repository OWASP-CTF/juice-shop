/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

function applyOperator (a: number, operator: string, b: number): number {
  switch (operator) {
    case '+':
      return a + b
    case '-':
      return a - b
    case '*':
      return a * b
    default:
      throw new Error(`Unsupported CAPTCHA operator: ${operator}`)
  }
}

// Evaluates a 3-term "a <op1> b <op2> c" expression while respecting standard
// operator precedence (multiplication before addition/subtraction), without
// resorting to eval()/Function() on a dynamically built string.
function calculateAnswer (firstTerm: number, firstOperator: string, secondTerm: number, secondOperator: string, thirdTerm: number): number {
  if (secondOperator === '*') {
    return applyOperator(firstTerm, firstOperator, applyOperator(secondTerm, secondOperator, thirdTerm))
  }
  return applyOperator(applyOperator(firstTerm, firstOperator, secondTerm), secondOperator, thirdTerm)
}

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
    const answer = calculateAnswer(firstTerm, firstOperator, secondTerm, secondOperator, thirdTerm).toString()

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
      // Invalidate the CAPTCHA once it has been solved correctly so the same
      // captchaId/answer pair cannot be replayed for further submissions.
      await captcha.destroy()
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
