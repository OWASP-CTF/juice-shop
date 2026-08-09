/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

/* The only thing keeping anyone off this page was that its address is long and unlisted, and the
   page recorded the reader's acknowledgement for whoever asked, with no check at all. An address
   is not an access control: it sits in the policy text, in the server logs and in every proxy
   history, so knowing it says nothing about who the caller is. The page is now served to callers
   the shop can actually identify, and the acknowledgement is recorded for that caller instead of
   for anyone who has seen the URL. The session is read from the Authorization header or the token
   cookie, so following the link from the policy in a browser still works. */
const readerOf = (req: Request) => {
  const fromHeader = utils.jwtFrom(req)
  const cookie = /(?:^|;\s*)token=([^;]*)/.exec(req.headers.cookie ?? '')
  const token = fromHeader ?? (cookie ? decodeURIComponent(cookie[1]) : undefined)
  if (!token || !security.verify(token)) {
    return undefined
  }
  return security.decode(token)?.data?.email
}

export function servePrivacyPolicyProof () {
  return (req: Request, res: Response) => {
    if (!readerOf(req)) {
      res.status(401).json({ error: 'Sign in to confirm you have read the privacy policy' })
      return
    }
    challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
  }
}
