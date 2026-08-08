/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const requestOrigin = req.headers.origin ?? req.headers.referer
    if (requestOrigin) {
      try {
        if (new URL(requestOrigin).origin !== new URL(config.get<string>('server.baseUrl')).origin) {
          res.status(403).json({ error: 'Cross-origin profile updates are not allowed' })
          return
        }
      } catch {
        res.status(403).json({ error: 'Invalid request origin' })
        return
      }
    }
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        next(new Error('User not found'))
        return
      }

      challengeUtils.solveIf(challenges.csrfChallenge, () => {
        return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
          (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
          req.body.username !== user.username
      })

      const savedUser = await user.update({ username: req.body.username })
      const userWithStatus = utils.queryResultToJson(savedUser)
      const updatedToken = security.authorize(userWithStatus)
      security.authenticatedUsers.put(updatedToken, userWithStatus)
      res.cookie('token', updatedToken, security.authCookieOptions)
      res.location(process.env.BASE_PATH + '/profile')
      res.redirect(process.env.BASE_PATH + '/profile')
    } catch (error) {
      next(error)
    }
  }
}
