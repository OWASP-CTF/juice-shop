/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

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
    /* Truncate first, then decide. The old order let a request be judged on a name the file
       system would never see: "package.json.bak%00.md" passed an extension test that only
       looked at the tail, and the truncation that ran afterwards handed a completely different
       file to sendFile. Deciding on the same string that is opened removes that gap entirely. */
    file = security.cutOffPoisonNullByte(file)

    if (file && isCustomerDocument(file)) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(file)

      res.sendFile(path.resolve('ftp/', file))
    } else {
      res.status(403)
      next(new Error('Only the terms of use and your own order confirmations are available for download!'))
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

  /* Matching on a file *extension* said nothing about whether a document was ever meant to be
     public - it happily served internal backups, key stores and stray developer leftovers that
     merely happen to end in .md, and the folder is full of them. The shop links exactly two
     kinds of document from this directory: its terms of use, and the confirmation PDF generated
     for an order (see routes/order.ts for the id format). Naming those two is an allow list of
     what belongs to customers, so every other file that ever lands in this folder - today's and
     tomorrow's - is out of reach without anyone having to remember to exclude it. */
  function isCustomerDocument (file: string) {
    return file === 'legal.md' || /^order_[0-9a-f]{4}-[0-9a-f]{16}\.pdf$/.test(file)
  }
}
