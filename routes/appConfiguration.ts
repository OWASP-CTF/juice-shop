/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

// This endpoint is unauthenticated and the client genuinely needs most of the
// configuration, so the whole object is served with the parts that are nobody's business
// removed. Two kinds of value are withheld:
//
//   - recovery secrets. The seeded memories carry the answers to the security questions
//     the password-reset flow accepts, so publishing the configuration published the
//     answers. Rotating them would only change which string is being given away.
//   - solution material. A handful of product entries name the file, URL or keywords that
//     a particular exercise turns on, which is internal detail rather than shop data.
const withheldMemoryFields = [
  'geoStalkingMetaSecurityAnswer',
  'geoStalkingVisualSecurityAnswer'
]

const withheldProductFields = [
  'exifForBlueprintChallenge',
  'fileForRetrieveBlueprintChallenge',
  'keywordsForPastebinDataLeakChallenge',
  'urlForProductTamperingChallenge',
  'useForChristmasSpecialChallenge'
]

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const safeConfig = structuredClone(config.util.toObject(config))
    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    if (Array.isArray(safeConfig.memories)) {
      for (const memory of safeConfig.memories) {
        for (const field of withheldMemoryFields) {
          delete memory[field]
        }
      }
    }
    if (Array.isArray(safeConfig.products)) {
      for (const product of safeConfig.products) {
        for (const field of withheldProductFields) {
          delete product[field]
        }
      }
    }
    res.json({ config: safeConfig })
  }
}
