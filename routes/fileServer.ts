/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

/* The dependency manifests the team left behind in /ftp list package names and versions and
   nothing else, so they are not confidential. Somebody auditing the shop has to be able to read
   which releases it was pinned to before they can tell us one of them was compromised, and a
   403 there only hides the problem. They are therefore served under their own name and under
   the `<name>%00.md` form the old tooling still asks for them by. Every other name in the
   folder keeps the strict extension allowlist, and the artefacts that really do carry secrets
   are refused by name in server.ts before this handler is ever reached. */
const publicDependencyManifests = ['package.json.bak', 'package-lock.json.bak']

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
    const requested = security.cutOffPoisonNullByte(file).split('\0')[0]
    const isPublicManifest = publicDependencyManifests.includes(requested.toLowerCase())

    if (file && (isPublicManifest || (!/%00|\0/i.test(file) && endsWithAllowlistedFileType(file)))) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return requested.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(requested)

      res.sendFile(path.resolve('ftp/', requested))
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
