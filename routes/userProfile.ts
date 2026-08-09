/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    // The username is text and nothing else. Substituting it into the template source put
    // it in front of the template engine, which reads #{...} as an expression to evaluate -
    // that is the injection this page is known for, and prefixing a backslash does not stop
    // it - and left any markup in it to be parsed as HTML afterwards. It is encoded once
    // here and placed into the finished markup further down, after the template has already
    // been compiled and rendered, so it never reaches the engine at all.
    const username = entities.encode(user.username ?? '')

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      // The stored profile image URL was pasted into the policy verbatim, so a value
      // carrying a semicolon appended directives of the caller's choosing. Only the origin
      // of a well-formed http(s) URL is allowed through, which keeps externally hosted
      // avatars working without letting any punctuation reach the header. 'unsafe-eval' is
      // not needed by this page and is gone.
      let imgSrc = "'self'"
      try {
        if (user?.profileImage && /^https?:\/\//i.test(user.profileImage)) {
          imgSrc += ' ' + new URL(user.profileImage).origin
        }
      } catch {
        imgSrc = "'self'"
      }
      const CSP = `img-src ${imgSrc}; script-src 'self'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      // Replacer function rather than a string, so no $-sequence in a username is treated
      // as a substitution pattern on the way in.
      res.send(fn(user).replace(/_username_/g, () => username))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
