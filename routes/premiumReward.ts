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
    // The only thing standing between this file and the public was the length of its path.
    // An unguessable URL is not an entitlement: it leaks through browser history, referrer
    // headers and access logs, and once it is known it stays known. The caller has to hold
    // the deluxe membership the content is sold with.
    if (!security.isDeluxe(req)) {
      res.status(403).json({ error: 'Premium content is available to deluxe members only' })
      return
    }
    challengeUtils.solveIf(challenges.premiumPaywallChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg'))
  }
}
