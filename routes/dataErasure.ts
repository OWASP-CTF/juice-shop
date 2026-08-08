/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import express, { type NextFunction, type Request, type Response } from 'express'
import config from 'config'
import { themes } from '../views/themes/themes'
import * as utils from '../lib/utils'
import { AllHtmlEntities as Entities } from 'html-entities'

import { SecurityQuestionModel } from '../models/securityQuestion'
import { PrivacyRequestModel } from '../models/privacyRequests'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as security from '../lib/insecurity'

const entities = new Entities()

const router = express.Router()

router.get('/', (req: Request, res: Response, next: NextFunction) => {
  void (async () => {
    const token = req.cookies.token
    const loggedInUser = security.verify(token) ? security.authenticatedUsers.get(token) : undefined
    const userId = loggedInUser?.data?.id
    const email = loggedInUser?.data?.email
    if (typeof userId !== 'number' || !Number.isSafeInteger(userId) || userId <= 0 || typeof email !== 'string') {
      res.status(401).send(res.__('You need to be logged in to request data erasure.'))
      return
    }

    try {
      const answer = await SecurityAnswerModel.findOne({
        where: { UserId: userId }
      })
      if (answer == null) {
        throw new Error('No answer found!')
      }
      const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
      if (question == null) {
        throw new Error('No question found!')
      }

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      res.render('dataErasureForm', {
        userEmail: email,
        securityQuestion: question.question,
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      })
    } catch (error) {
      next(error)
    }
  })()
})

interface DataErasureRequestParams {
  layout?: unknown
  email?: unknown
  securityAnswer?: unknown
}

router.post('/', (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): void => {
  void (async () => {
    const token = req.cookies.token
    const loggedInUser = security.verify(token) ? security.authenticatedUsers.get(token) : undefined
    const userId = loggedInUser?.data?.id
    const email = loggedInUser?.data?.email
    if (typeof userId !== 'number' || !Number.isSafeInteger(userId) || userId <= 0 || typeof email !== 'string') {
      res.status(401).send(res.__('You need to be logged in to request data erasure.'))
      return
    }

    try {
      if (req.body.layout !== undefined && req.body.layout !== null && req.body.layout !== '') {
        res.status(400).send(res.__('Invalid data erasure request.'))
        return
      }
      if (typeof req.body.email !== 'string' || req.body.email.toLowerCase() !== email.toLowerCase()) {
        res.status(403).send(res.__('The supplied email does not belong to the authenticated user.'))
        return
      }
      if (typeof req.body.securityAnswer !== 'string' || req.body.securityAnswer.length === 0) {
        res.status(400).send(res.__('A security answer is required.'))
        return
      }

      const storedAnswer = await SecurityAnswerModel.findOne({ where: { UserId: userId } })
      if (storedAnswer == null || security.hmac(req.body.securityAnswer) !== storedAnswer.answer) {
        res.status(401).send(res.__('Wrong answer to security question.'))
        return
      }

      await PrivacyRequestModel.create({
        UserId: userId,
        deletionRequested: true
      })

      res.clearCookie('token')

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      const themeVars = {
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      }

      res.render('dataErasureResult', themeVars)
    } catch (error) {
      next(error)
    }
  })()
})

export default router
