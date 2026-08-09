/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

const NULL_BYTE = String.fromCharCode(0)

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    // The allowlist had a hole cut in it for one file: incident-support.kdbx, a password
    // database that nobody browsing the shop has any business downloading. The exception is
    // gone, so only the document types this endpoint is meant to hand out get served.
    if (file && !containsPoisonNullByte(file) && endsWithAllowlistedFileType(file)) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })

      res.sendFile(path.resolve('ftp/', file))
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function containsPoisonNullByte (param: string) {
    return param.includes(NULL_BYTE) || param.toLowerCase().includes('%00')
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
