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
    // The answer stays server-side. Returning it alongside the expression let a client
    // read the solution straight out of the response instead of solving it.
    res.json({ captchaId, captcha: expression })
  }
}

// A CAPTCHA only proves that someone solved an arithmetic expression, which a script does
// as easily as a customer. The anti-automation part is the pace: complaints arrive one at
// a time, so redemptions from one address are capped over a short rolling window.
const REDEMPTION_WINDOW_MS = 20000
const MAX_REDEMPTIONS_PER_WINDOW = 4
const redemptionsByClient = new Map<string, number[]>()

function recordRedemption (client: string) {
  const now = Date.now()
  const recent = (redemptionsByClient.get(client) ?? []).filter((at) => now - at < REDEMPTION_WINDOW_MS)
  const withinLimit = recent.length < MAX_REDEMPTIONS_PER_WINDOW
  if (withinLimit) {
    recent.push(now)
  }
  if (recent.length > 0) {
    redemptionsByClient.set(client, recent)
  } else {
    redemptionsByClient.delete(client)
  }
  if (redemptionsByClient.size > 1000) {
    for (const [key, times] of redemptionsByClient) {
      if (times.every((at) => now - at >= REDEMPTION_WINDOW_MS)) {
        redemptionsByClient.delete(key)
      }
    }
  }
  return withinLimit
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      // A solved CAPTCHA is redeemed once. Leaving the row in place let one solution
      // authorise an unlimited number of submissions.
      await CaptchaModel.destroy({ where: { captchaId: req.body.captchaId } })
      // Keyed on the peer address rather than req.ip: the application trusts proxy
      // headers, and a forwarded-for value the caller sets is no basis for a limit.
      if (!recordRedemption(req.socket.remoteAddress ?? req.ip ?? 'unknown')) {
        res.status(429).send('Too many submissions in a short time. Please try again in a moment.')
        return
      }
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
