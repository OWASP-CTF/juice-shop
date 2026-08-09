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

// A CSP source expression is a single token: whitespace ends it and ';' starts a
// whole new directive. Interpolating a user-controlled profile image URL that
// carries either of those therefore lets the user append directives of their own
// (e.g. "; script-src 'self' 'unsafe-inline'") and relax the policy that is
// supposed to protect this page. Keep only the leading run of characters a URL
// source expression may legitimately contain, and drop the value entirely if
// anything else shows up, so nothing can escape the img-src directive.
function cspImageSource (profileImage: string | undefined): string {
  if (!profileImage) {
    return ''
  }
  return /^[\w.:/?#=&%+~-]+$/.test(profileImage) ? profileImage : ''
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

    // SSTi (Challenge-74) is closed here structurally: the username is never spliced into
    // the Pug template *source*, so no interpolation form (#{...} / !{...} / #[...]) can
    // ever reach the compiler and be evaluated as server-side JavaScript. See the comment
    // on the template replacements below - it is injected into the already-compiled HTML
    // instead, entity-encoded, where only the browser can interpret it.
    const username = user.username ?? ''

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    // The username is deliberately NOT substituted into `template`. Everything put
    // there becomes Pug *source* that is handed to the compiler below, and Pug source
    // has several interpolation forms - #{...}, !{...}, #[...] - whose contents are
    // evaluated as JavaScript on the server. HTML-encoding cannot make a value safe to
    // feed to a compiler: it leaves '!', '{' and '}' untouched, so the unescaped
    // !{...} form survives encoding and turns a display string into server-side code
    // execution. The name is a piece of data about the page, not part of its markup, so
    // it is put into the finished HTML after compilation instead, where the only thing
    // that can interpret it is the browser and plain entity-encoding is exactly right.
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
      const imgSrc = ["'self'", cspImageSource(user?.profileImage)].filter(Boolean).join(' ')
      // 'unsafe-eval' is gone with the template evaluation that used to need it.
      const CSP = `img-src ${imgSrc}; script-src 'self'`

      // Substituted into the rendered page rather than into the Pug source, so no
      // interpolation form ever reaches the compiler. The replacement is a callback
      // because a replacement *string* would let '$&' or "$'" in a name expand into
      // the surrounding markup - a splice that entity-encoding does not cover.
      const encodedUsername = entities.encode(username)

      // The name is inspected in the form it is actually rendered in, so a payload that has been
      // encoded out of existence is no longer reported as an injection. `match` yields null when
      // nothing matched and the whole expression is undefined when there is no profile image at
      // all, so the result is coerced instead of compared - an optional chain that short-circuits
      // used to make this read as "not null" and hold for every visitor.
      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return Boolean(encodedUsername) && Boolean(user?.profileImage?.match(/;[ ]*script-src(.)*'unsafe-inline'/g)) && utils.contains(encodedUsername, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user).replace(/_username_/g, () => encodedUsername))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
