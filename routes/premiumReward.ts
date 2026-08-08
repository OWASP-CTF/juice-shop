/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'

export function servePremiumContent () {
  return (req: Request, res: Response) => {
    if (!security.isDeluxe(req)) {
      res.status(403).json({ error: 'Deluxe membership required' })
      return
    }
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg'))
  }
}
