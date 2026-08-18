/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import { ImageCaptchaModel } from '../models/imageCaptcha'
import * as security from '../lib/insecurity'

export function imageCaptchas () {
  return async (req: Request, res: Response) => {
    try {
      const { default: svgCaptcha } = await import('svg-captcha')
      const captcha = svgCaptcha.create({ size: 5, noise: 2, color: true })

      const user = security.authenticatedUsers.from(req)
      if (!user) {
        res.status(401).send(res.__('You need to be logged in to request a CAPTCHA.'))
        return
      }

      const imageCaptcha = {
        image: captcha.data,
        answer: captcha.text,
        UserId: user.data.id
      }
      const imageCaptchaInstance = ImageCaptchaModel.build(imageCaptcha)
      await imageCaptchaInstance.save()
      /* The whole point of the puzzle is that only a human looking at the picture knows the
         solution, so the solution must not travel back with the picture. Only the image and
         the account it belongs to are sent; the answer stays in the row saved above, which is
         where the check below reads it from. */
      res.json({ image: imageCaptcha.image, UserId: imageCaptcha.UserId })
    } catch (error) {
      res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
    }
  }
}

export const verifyImageCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = security.authenticatedUsers.from(req)
    /* Without a session there is no account to look a puzzle up for, and the lookup below then
       matched nothing - which the old check read as "no captcha was ever issued" and waved
       through. An anonymous caller is turned away instead. */
    if (!user?.data) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }
    const UserId = user.data.id
    const captchas = await ImageCaptchaModel.findAll({
      limit: 1,
      where: {
        UserId,
        createdAt: {
          [Op.gt]: new Date(Date.now() - 300000)
        }
      },
      order: [['createdAt', 'DESC']]
    })
    /* Two separate holes were in the old condition. A missing puzzle counted as a pass, so a
       caller who simply never asked for one sailed through; and a matched puzzle was left in
       place, so one correct answer could be replayed for five minutes. Deleting the row is
       what makes the proof single use: exactly the one request that removes it continues, and
       every later submission of the same answer finds nothing to redeem. */
    const redeemed = (captchas[0] && req.body.answer === captchas[0].answer)
      ? await ImageCaptchaModel.destroy({ where: { id: captchas[0].id } })
      : 0
    if (redeemed === 1) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    res.status(401).send(res.__('Something went wrong while submitting CAPTCHA. Please try again.'))
  }
}
