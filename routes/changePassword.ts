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
  return async ({ query, headers, connection }: Request, res: Response, next: NextFunction) => {
    const currentPassword = query.current as string
    const newPassword = query.new as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = query.repeat

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

    /* The current password is a mandatory part of this request, not an optional extra. Only
       checking it when the caller happened to supply one means omitting the parameter skipped
       the check altogether, so anybody able to make the browser send its ambient session (a
       link, an image tag, a form on another site) could rewrite the account's password without
       ever knowing it. An absent value is therefore treated exactly like a wrong one. */
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
      /* The cached session still carries the credential it was minted against, so it has to
         follow the new password instead of outliving it. */
      loggedInUser.data.password = user.password
      challengeUtils.solveIf(
        challenges.changePasswordBenderChallenge,
        () => user.id === 3 && !currentPassword && user.password === security.hash('slurmCl4ssic')
      )
      /* The full model row carries the password hash and the TOTP secret; the caller only has
         to learn which account was changed. */
      res.json({ user: { id: user.id, email: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
