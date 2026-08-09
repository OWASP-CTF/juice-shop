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
    // The secret URL itself is only ever obfuscation - it lives in plainly readable,
    // version-controlled server source, so knowing it proves nothing. Solving must also
    // require the real, server-tracked precondition (having actually opened the privacy
    // policy, per accessControlChallenges' '/81px.png' tracker) instead of trusting the
    // path alone as the sole gate.
    challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => { return challenges.privacyPolicyChallenge?.solved === true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
  }
}
