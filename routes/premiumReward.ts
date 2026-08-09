/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'

export function servePremiumContent () {
  return (req: Request, res: Response) => {
    /* The wallpaper is the reward for a deluxe membership and lives under assets/private, but the
       only thing standing in front of it was the length of the path. A URL nobody has been told
       is not a paywall: it is guessed, shared, recorded by proxies and left in browser history,
       and it gives the same access to everyone who ends up holding it -- including the people who
       never paid, which is the entire point of the resource being restricted.

       Membership is a property of the caller, so it is read from the caller's own token. */
    if (!security.isDeluxe(req)) {
      res.status(402).json({ error: 'This content is for deluxe members only.' })
      return
    }
    challengeUtils.solveIf(challenges.premiumPaywallChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg'))
  }
}
