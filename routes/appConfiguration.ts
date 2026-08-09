/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

/* The configuration document is handed to every visitor so the client can render itself, but it
   also carries operational detail the client has no use for and no business seeing. Those fields
   are removed before the document leaves the server, rather than being relied on to stay unnoticed
   behind an /rest/admin/ path that nothing actually authorises. */
const INTERNAL_APPLICATION_SETTINGS = [
  'overwriteUrlForProductTamperingChallenge',
  'xssBonusPayload',
  'csafHashValue',
  'metricsIgnoredUserAgents'
]
const INTERNAL_PRODUCT_SETTINGS = [
  'urlForProductTamperingChallenge',
  'keywordsForPastebinDataLeakChallenge',
  'fileForRetrieveBlueprintChallenge',
  'exifForBlueprintChallenge',
  'useForChristmasSpecialChallenge'
]
/* Answers to the security questions used for account recovery. Publishing them is the same as
   publishing the credentials themselves. */
const INTERNAL_MEMORY_SETTINGS = [
  'geoStalkingMetaSecurityAnswer',
  'geoStalkingVisualSecurityAnswer'
]

function withoutKeys (value: any, keys: string[]) {
  if (value === null || typeof value !== 'object') {
    return value
  }
  for (const key of keys) {
    delete value[key]
  }
  return value
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const safeConfig = structuredClone(config.util.toObject(config))
    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    withoutKeys(safeConfig.challenges, INTERNAL_APPLICATION_SETTINGS)
    if (Array.isArray(safeConfig.products)) {
      for (const product of safeConfig.products) {
        withoutKeys(product, INTERNAL_PRODUCT_SETTINGS)
      }
    }
    if (Array.isArray(safeConfig.memories)) {
      for (const memory of safeConfig.memories) {
        withoutKeys(memory, INTERNAL_MEMORY_SETTINGS)
      }
    }
    res.json({ config: safeConfig })
  }
}
