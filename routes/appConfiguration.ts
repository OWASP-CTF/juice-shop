/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

import { isTokenSaleAudience } from './tokenSale'

export function retrieveAppConfiguration () {
  return (req: Request, res: Response) => {
    const safeConfig = structuredClone(config.util.toObject(config))
    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    /* The name of the unreleased altcoin is token sale material and must not be handed
       to callers who were never granted access to the token sale itself. */
    if (safeConfig.application && !isTokenSaleAudience(req)) {
      delete safeConfig.application.altcoinName
    }
    res.json({ config: safeConfig })
  }
}
