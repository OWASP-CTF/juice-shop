/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as utils from '../lib/utils'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function changePassword () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const currentPassword = req.body.current as string
    const newPassword = req.body.new as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = req.body.repeat

    if (!currentPassword || !newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser) {
      res.status(401).send(res.__('You need to be logged in to change your password.'))
      return
    }

    if (!security.verifyPassword(currentPassword, loggedInUser.data.password)) {
      res.status(401).send(res.__('Current password is not correct.'))
      return
    }

    try {
      const user = await UserModel.scope('withSensitive').findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }

      await user.update({ password: newPasswordInString })
      security.authenticatedUsers.updateFrom(req, utils.queryResultToJson(user))
      res.json({
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          profileImage: user.profileImage
        }
      })
    } catch (error) {
      next(error)
    }
  }
}
