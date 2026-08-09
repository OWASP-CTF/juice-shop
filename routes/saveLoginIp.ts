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
      // The header is attacker-authored text that later shows up on a page of the shop, so it is
      // stripped of markup straight away - before anything else looks at it. Cleaning it only
      // after the inspection below would leave the shop reporting an injection it is not carrying.
      if (lastLoginIp !== undefined) {
        lastLoginIp = security.sanitizeSecure(lastLoginIp)
      }
      if (utils.isChallengeEnabled(challenges.httpHeaderXssChallenge)) {
        challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return lastLoginIp === '<iframe src="javascript:alert(`xss`)">' })
      }
      if (lastLoginIp === undefined || lastLoginIp === '') {
        lastLoginIp = utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      }
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
        // Only the handful of attributes the caller asked about travel back. The full record also
        // carries the password hash and the TOTP seed, neither of which belongs in a response to
        // a request that merely recorded a login address.
        res.json(updatedUser
          ? {
              id: updatedUser.id,
              email: updatedUser.email,
              username: updatedUser.username,
              profileImage: updatedUser.profileImage,
              lastLoginIp: updatedUser.lastLoginIp
            }
          : updatedUser)
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
