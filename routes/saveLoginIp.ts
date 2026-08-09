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
      const token = utils.jwtFrom(req)
      let lastLoginIp = req.headers['true-client-ip']
      if (Array.isArray(lastLoginIp)) {
        lastLoginIp = lastLoginIp[0]
      }
      challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return lastLoginIp === '<iframe src="javascript:alert(`xss`)">' })
      /* The true-client-ip header is attacker controlled and is rendered back on
         the profile page, so it was stored XSS whenever the value skipped the
         sanitiser. It is now sanitised whenever the header is present, and the
         connection address is still used when it is not. */
      if (lastLoginIp !== undefined) {
        lastLoginIp = security.sanitizeSecure(lastLoginIp)
      } else {
        lastLoginIp = utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      }
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
        /* Returning the model verbatim handed back every column, including the
           stored password hash and the TOTP secret, to anyone hitting this
           endpoint. Only the fields the caller needs are echoed. */
        res.json({
          id: updatedUser?.id,
          email: updatedUser?.email,
          lastLoginIp: updatedUser?.lastLoginIp,
          profileImage: updatedUser?.profileImage
        })
      } catch (error) {
        next(error)
      } finally {
        /* The frontend calls this endpoint as its final logout action. Session
           revocation must not depend on successfully storing an audit field. */
        security.authenticatedUsers.remove(token)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
