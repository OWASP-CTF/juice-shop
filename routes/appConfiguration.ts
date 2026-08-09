/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

const SENSITIVE = /(key|secret|token|hash|password|mnemonic|seed|credential)/i

/* The storefront needs the branding and catalogue settings to render, so the endpoint keeps
   answering. What it stops doing is handing the deployment's internal settings to whoever asks:
   an unlisted-looking path is not an access control, so the sensitive half is withheld unless the
   caller is actually an administrator. */
function withhold (value: any): any {
  if (Array.isArray(value)) return value.map(withhold)
  if (value && typeof value === 'object') {
    const out: any = {}
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE.test(k)) continue
      out[k] = withhold(v)
    }
    return out
  }
  return value
}

export function retrieveAppConfiguration () {
  return (req: Request, res: Response) => {
    const safeConfig = structuredClone(config.util.toObject(config))
    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    const user = security.authenticatedUsers.from(req)
    if (user?.data?.role === security.roles.admin) {
      res.json({ config: safeConfig })
      return
    }
    delete safeConfig.challenges
    res.json({ config: withhold(safeConfig) })
  }
}
