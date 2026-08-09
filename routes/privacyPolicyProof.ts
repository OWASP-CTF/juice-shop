/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePrivacyPolicyProof () {
  return (req: Request, res: Response) => {
    // Knowing this path is not proof of anything - it sits in plainly readable server
    // source, so anyone can reach it without ever having opened the privacy policy. The
    // obscure URL was previously the *only* gate on the proof image, so simply requesting
    // it disclosed the resource to anyone. Actually require the precondition it claims:
    // that the privacy policy page view beacon (tracked independently in verify.ts)
    // already fired for this session.
    if (challenges.privacyPolicyChallenge?.solved !== true) {
      res.status(403).end()
      return
    }
    challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
  }
}
