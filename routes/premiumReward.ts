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
    /* The wallpaper behind this URL is the reward for a paid membership, so the membership is
       what has to be presented to get it. Relying on the path being long and undocumented is
       not access control - the string ships inside the client bundle that every visitor
       downloads - so the entitlement is checked here, on the server, before the file is sent. */
    if (!security.isDeluxe(req)) {
      res.status(403).json({ error: 'This content is reserved for deluxe members.' })
      return
    }
    challengeUtils.solveIf(challenges.premiumPaywallChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg'))
  }
}
