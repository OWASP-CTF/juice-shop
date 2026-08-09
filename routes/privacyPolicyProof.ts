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
    // source, so anyone can reach it without ever having opened the privacy policy.
    // The proof must actually require the precondition it claims: that the privacy
    // policy page view beacon (tracked independently in verify.ts) already fired.
    challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => { return challenges.privacyPolicyChallenge?.solved === true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
  }
}
