/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { isIP } from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

function validIp (value: string | string[] | undefined) {
  const candidate = Array.isArray(value) ? value[0] : value
  if (candidate === undefined) {
    return undefined
  }

  const ip = utils.toSimpleIpAddress(candidate.trim())
  return isIP(ip) !== 0 ? ip : undefined
}

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      const lastLoginIp = validIp(req.headers['true-client-ip']) ?? validIp(req.socket.remoteAddress)
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = lastLoginIp === undefined ? user : await user?.update({ lastLoginIp })
        res.json(updatedUser)
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
