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
      // Only the rendered image goes back to the caller. The text it depicts is the
      // answer, and returning it made reading the CAPTCHA unnecessary.
      res.json({ image: captcha.data })
    } catch (error) {
      res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
    }
  }
}

export const verifyImageCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = security.authenticatedUsers.from(req)
    const UserId = user ? user.data ? user.data.id : undefined : undefined
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
    // An absent CAPTCHA used to satisfy this check, so skipping the request for one - or
    // simply waiting for it to age out - passed verification without answering anything.
    if (captchas[0] && req.body.answer === captchas[0].answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    res.status(401).send(res.__('Something went wrong while submitting CAPTCHA. Please try again.'))
  }
}
