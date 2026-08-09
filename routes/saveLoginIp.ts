/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import net from 'node:net'
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
      // The header is fully attacker controlled, so it is only accepted when it really is
      // an IP address. Anything else falls back to the address of the actual connection.
      if (typeof lastLoginIp !== 'string' || net.isIP(lastLoginIp.trim()) === 0) {
        lastLoginIp = utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      } else {
        lastLoginIp = lastLoginIp.trim()
      }
      challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return lastLoginIp === '<iframe src="javascript:alert(`xss`)">' })
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
        res.json(updatedUser)
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
