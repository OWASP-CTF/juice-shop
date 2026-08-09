/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

// Sitting the endpoint under /rest/admin never restricted it. The storefront needs the branding
// and these five switches; everything else is operational detail - deployment hashes, seed data
// and the payloads and override URLs the exercises are built on - so only an administrator is
// answered the whole document.
const publicChallengeSettings = [
  'showSolvedNotifications',
  'showHints',
  'showMitigations',
  'codingChallengesEnabled',
  'restrictToTutorialsFirst',
  'safetyMode'
]

export function retrieveAppConfiguration () {
  return (req: Request, res: Response) => {
    const fullConfig = structuredClone(config.util.toObject(config))
    if (fullConfig.application?.chatBot) {
      delete fullConfig.application.chatBot.llmApiUrl
    }

    if (security.isAdminRequest(req)) {
      res.json({ config: fullConfig })
      return
    }

    const challenges: Record<string, unknown> = {}
    for (const setting of publicChallengeSettings) {
      if (fullConfig.challenges?.[setting] !== undefined) {
        challenges[setting] = fullConfig.challenges[setting]
      }
    }
    res.json({
      config: {
        application: fullConfig.application,
        hackingInstructor: fullConfig.hackingInstructor,
        ctf: fullConfig.ctf,
        challenges
      }
    })
  }
}
