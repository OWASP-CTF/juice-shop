/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

export function retrieveAppConfiguration () {
  return (req: Request, res: Response) => {
    if (!security.isAdmin(req)) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const safeConfig = structuredClone(config.util.toObject(config))
    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    res.json({ config: safeConfig })
  }
}
