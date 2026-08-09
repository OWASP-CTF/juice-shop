/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

/* The configuration document mixes two very different things: the presentation settings the client
   needs in order to render itself, and operational detail that only an administrator has any business
   reading. The endpoint lives under /rest/admin/ but nothing authorises it, so today every visitor
   receives both. Sitting behind an administrative-looking path is not an access control.

   Callers therefore get one of two views of the same resource: administrators get the document
   unchanged, everyone else gets it with the settings below removed. */

/* Unannounced commercial detail. `altcoinName` is the name of the token the shop has not launched
   yet - it is the substance of the token sale page and is not public until that page is. */
const ADMINISTRATIVE_APPLICATION_SETTINGS = ['altcoinName']

/* Answers to the security questions used for account recovery. Publishing an answer publishes the
   credential, so only the questions themselves may leave the server. */
const ADMINISTRATIVE_MEMORY_SETTINGS = [
  'geoStalkingMetaSecurityAnswer',
  'geoStalkingVisualSecurityAnswer'
]

/* Internal expected values and monitoring configuration. `metricsIgnoredUserAgents` in particular
   describes how to move through the shop without appearing in its own metrics. */
const ADMINISTRATIVE_CHALLENGE_SETTINGS = [
  'overwriteUrlForProductTamperingChallenge',
  'xssBonusPayload',
  'csafHashValue',
  'metricsIgnoredUserAgents'
]

/* Per-product internal wiring, none of which the storefront renders. */
const ADMINISTRATIVE_PRODUCT_SETTINGS = [
  'urlForProductTamperingChallenge',
  'keywordsForPastebinDataLeakChallenge',
  'fileForRetrieveBlueprintChallenge',
  'exifForBlueprintChallenge',
  'useForChristmasSpecialChallenge'
]

function withoutSettings (value: unknown, settings: string[]) {
  if (value === null || typeof value !== 'object') {
    return
  }
  for (const setting of settings) {
    delete (value as Record<string, unknown>)[setting]
  }
}

export function retrieveAppConfiguration () {
  return (req: Request, res: Response) => {
    const appConfiguration = structuredClone(config.util.toObject(config))
    if (appConfiguration.application?.chatBot) {
      delete appConfiguration.application.chatBot.llmApiUrl
    }

    if (!security.isAdmin(req)) {
      withoutSettings(appConfiguration.application, ADMINISTRATIVE_APPLICATION_SETTINGS)
      withoutSettings(appConfiguration.challenges, ADMINISTRATIVE_CHALLENGE_SETTINGS)
      if (Array.isArray(appConfiguration.memories)) {
        for (const memory of appConfiguration.memories) {
          withoutSettings(memory, ADMINISTRATIVE_MEMORY_SETTINGS)
        }
      }
      if (Array.isArray(appConfiguration.products)) {
        for (const product of appConfiguration.products) {
          withoutSettings(product, ADMINISTRATIVE_PRODUCT_SETTINGS)
        }
      }
    }

    res.json({ config: appConfiguration })
  }
}
