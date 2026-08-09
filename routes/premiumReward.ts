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
    challengeUtils.solveIf(challenges.premiumPaywallChallenge, () => { return true })
    // The path being long is not an entitlement. Premium content requires a deluxe membership.
    if (!security.isDeluxe(req)) {
      res.status(403).json({ error: 'Premium content is available to deluxe members only' })
      return
    }
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg'))
  }
}
