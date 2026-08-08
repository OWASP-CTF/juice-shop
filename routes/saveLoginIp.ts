/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import net from 'node:net'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      const headerIp = Array.isArray(req.headers['true-client-ip']) ? req.headers['true-client-ip'][0] : req.headers['true-client-ip']
      const lastLoginIp = typeof headerIp === 'string' && net.isIP(headerIp) !== 0
        ? headerIp
        : utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
        if (!updatedUser) {
          res.sendStatus(404)
          return
        }
        res.json({
          id: updatedUser.id,
          email: updatedUser.email,
          lastLoginIp: updatedUser.lastLoginIp,
          profileImage: updatedUser.profileImage
        })
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
