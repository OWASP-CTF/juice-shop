/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      let lastLoginIp = req.headers['true-client-ip']
      if (Array.isArray(lastLoginIp)) {
        lastLoginIp = lastLoginIp[0]
      }
      if (lastLoginIp !== undefined) {
        lastLoginIp = security.sanitizeSecure(lastLoginIp)
      }
      if (utils.isChallengeEnabled(challenges.httpHeaderXssChallenge)) {
        challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return lastLoginIp === '<iframe src="javascript:alert(`xss`)">' })
      }
      if (lastLoginIp === undefined) {
        lastLoginIp = utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      }
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
        // The whole model carries the password hash and the TOTP secret; the caller asked only
        // where it last signed in from.
        res.json(updatedUser && { id: updatedUser.id, email: updatedUser.email, lastLoginIp: updatedUser.lastLoginIp, profileImage: updatedUser.profileImage })
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
