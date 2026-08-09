/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function changePassword () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { headers } = req
    // The credentials used to arrive in the query string of a GET, which puts the old and
    // new password into access logs, browser history and referrer headers, and makes the
    // change reachable by a cross-site GET. They are read from the body now; the query is
    // kept only as a fallback so a client mid-flight is not broken.
    const params = { ...req.query, ...req.body }
    const currentPassword = params.current as string
    const newPassword = params.new as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = params.repeat

    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null
    if (token === null) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    if (!currentPassword || security.hash(currentPassword) !== loggedInUser.data.password) {
      res.status(401).send(res.__('Current password is not correct.'))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }

      await user.update({ password: newPasswordInString })
      challengeUtils.solveIf(
        challenges.changePasswordBenderChallenge,
        () => user.id === 3 && !currentPassword && user.password === security.hash('slurmCl4ssic')
      )
      // The response used to carry the whole user record, so a password change answered with
      // the freshly stored hash and the TOTP secret.
      res.json({ user: { id: user.id, email: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
