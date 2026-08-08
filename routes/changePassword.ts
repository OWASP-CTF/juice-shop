/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function changePassword () {
  return async ({ body, query, headers, connection }: Request, res: Response, next: NextFunction) => {
    // Accept parameters from the request body (POST). A query-string fallback is kept so
    // that legacy callers keep working, but the credential is never leaked via the URL for
    // proper POST requests.
    const currentPassword = (body?.current ?? query.current) as string
    const newPassword = (body?.new ?? query.new) as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = body?.repeat ?? query.repeat

    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null
    if (token === null) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    // The current password MUST be supplied and MUST match on every change. Previously the
    // verification was skipped entirely when no current password was provided, which allowed a
    // logged-in user's password to be overwritten without proof of knowledge of the old one
    // (exploitable via CSRF because the endpoint was a GET). Require and verify it unconditionally.
    if (!currentPassword) {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    }
    if (security.hash(currentPassword) !== loggedInUser.data.password) {
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
      res.json({ user })
    } catch (error) {
      next(error)
    }
  }
}
