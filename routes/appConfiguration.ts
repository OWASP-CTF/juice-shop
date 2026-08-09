/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

/* This endpoint hands the whole server configuration to whoever asks for it. It sits under a
   path that reads as if it were administrative, but nothing about it is restricted - the shop's
   own start-up screen needs it before anybody has logged in, so it cannot be. The path was doing
   the job a permission check should have been doing, and a path is not a secret: it is written
   into the bundle every visitor downloads.

   The answer is not to lock the endpoint, which would stop the shop from starting up for
   customers, but to stop putting things behind it that were never meant to leave the server.
   Handing out the entire configuration object meant handing out deployment details and, worse,
   the settings that exist purely to arrange the security exercises - the hash a researcher is
   supposed to derive for themselves, the address a tampered product is supposed to be steered
   to, the file name behind a paid-for blueprint, the keywords that identify a leaked product.
   Those are answers, and reading them off a public endpoint is not the intended route to any of
   them.

   So the response is assembled from the parts the browser client actually reads rather than
   filtered down from everything. Anything added to the configuration later is therefore private
   until somebody deliberately lists it here, which is the safe direction for that mistake to
   fall. */

const PUBLIC_CHALLENGE_SETTINGS = [
  'showSolvedNotifications',
  'showHints',
  'showMitigations',
  'codingChallengesEnabled',
  'restrictToTutorialsFirst',
  'safetyMode'
] as const

const PUBLIC_CTF_SETTINGS = [
  'showFlagsInNotifications',
  'showCountryDetailsInNotifications',
  'systemWideNotifications'
] as const

const pick = <T extends Record<string, unknown>>(source: T | undefined, keys: readonly string[]) => {
  const picked: Record<string, unknown> = {}
  if (!source) {
    return picked
  }
  for (const key of keys) {
    if (source[key] !== undefined) {
      picked[key] = source[key]
    }
  }
  return picked
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const fullConfig = structuredClone(config.util.toObject(config))
    const application = fullConfig.application ?? {}
    if (application.chatBot) {
      delete application.chatBot.llmApiUrl
    }
    res.json({
      config: {
        application,
        hackingInstructor: fullConfig.hackingInstructor,
        challenges: pick(fullConfig.challenges, PUBLIC_CHALLENGE_SETTINGS),
        ctf: pick(fullConfig.ctf, PUBLIC_CTF_SETTINGS)
      }
    })
  }
}
