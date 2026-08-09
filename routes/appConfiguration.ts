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
    /* This endpoint is public, so it may only ever carry values the shop is happy to show every
       visitor. The seeded security-question answers are credential-recovery secrets: publishing
       them here hands over every account they protect, no matter how strong the answers are. */
    if (Array.isArray(safeConfig.memories)) {
      for (const memory of safeConfig.memories) {
        delete memory.geoStalkingMetaSecurityAnswer
        delete memory.geoStalkingVisualSecurityAnswer
      }
    }
    res.json({ config: safeConfig })
  }
}
