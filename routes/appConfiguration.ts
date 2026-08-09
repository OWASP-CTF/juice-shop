/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

// The storefront reads only these sections. The rest is server-side deployment detail and seed
// data - the product list names every withdrawn product and the files behind them, and the
// memories name the photos - so it is answered to nobody.
const storefrontSections = ['application', 'challenges', 'hackingInstructor', 'ctf']

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const fullConfig = config.util.toObject(config)
    const safeConfig: Record<string, any> = {}
    for (const section of storefrontSections) {
      if (fullConfig[section] !== undefined) {
        safeConfig[section] = structuredClone(fullConfig[section])
      }
    }
    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    res.json({ config: safeConfig })
  }
}
