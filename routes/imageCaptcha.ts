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
      res.json(imageCaptcha)
    } catch (error) {
      res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
    }
  }
}

export const verifyImageCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = security.authenticatedUsers.from(req)
    const UserId = user?.data?.id
    if (UserId === undefined) {
      // Without a UserId, sequelize drops the key from the WHERE clause entirely and the
      // query matches the newest CAPTCHA belonging to *any* user.
      res.status(401).send(res.__('You need to be logged in to solve a CAPTCHA.'))
      return
    }
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
    // Absence of a CAPTCHA must fail closed. Previously "!captchas[0] ||" let anyone who
    // simply never requested one (or waited out the 5 minute window) skip verification.
    if (captchas[0] && req.body.answer === captchas[0].answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    res.status(401).send(res.__('Something went wrong while submitting CAPTCHA. Please try again.'))
  }
}
