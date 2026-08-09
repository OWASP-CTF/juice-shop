/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const safeConfig = structuredClone(config.util.toObject(config))
    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    // The coin is unannounced, so its name is not the storefront's to hand out either.
    delete safeConfig.application?.altcoinName
    delete safeConfig.products
    delete safeConfig.memories
    delete safeConfig.server
    res.json({ config: safeConfig })
  }
}
