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
    /* The unreleased coin is the token sale's own subject matter. This endpoint answers
       anybody, so publishing the name here handed the details of an unannounced offering to
       callers who were never given access to it - no need to find the page at all. The sale
       screen carries its own default, so it still renders for the audience it is meant for. */
    if (safeConfig.application) {
      delete safeConfig.application.altcoinName
    }
    res.json({ config: safeConfig })
  }
}
