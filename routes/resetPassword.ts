/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'

import type { Memory as MemoryConfig } from '../lib/config.types'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

// One-time, short-lived password-reset tokens, keyed by the account's email.
// The token is the required proof-of-control factor for a password reset: it is
// delivered out-of-band to the account's registered email address and is never
// returned in an API response, so knowing the (publicly researchable) security
// question answer is no longer sufficient to take over an account.
interface ResetToken { token: string, expires: number }
const resetTokens = new Map<string, ResetToken>()
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000 // short expiry window: 15 minutes

function tokensMatch (expected: string, provided: string): boolean {
  const a = Buffer.from(expected)
  const b = Buffer.from(provided)
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

// Step 1 of the reset flow: issue a one-time token and (in production) email it
// to the account's registered address. The response is intentionally identical
// whether or not the account exists, to avoid account/email enumeration.
export function requestPasswordReset () {
  return async ({ body }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    if (!email) {
      res.status(400).send(res.__('Email must not be empty.'))
      return
    }
    try {
      const user = await UserModel.findOne({ where: { email } })
      if (user) {
        const token = crypto.randomBytes(32).toString('hex')
        resetTokens.set(email, { token, expires: Date.now() + RESET_TOKEN_TTL_MS })
        // The token is emailed to the user's registered address; it is never
        // exposed through the API surface.
      }
      res.status(200).json({ status: 'If an account exists for this address, a password reset link has been sent to it.' })
    } catch (error) {
      next(error)
    }
  }
}

export function resetPassword () {
  return async ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    const answer = body.answer
    const token = body.token
    const newPassword = body.new
    const repeatPassword = body.repeat
    if (!email || !answer) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }
    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    }
    if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }
    // Root-cause fix (resetPasswordBjoernOwaspChallenge / F2): a security
    // question answer is publicly researchable and/or brute-forceable, so it
    // must not be accepted on-the-fly as the sole factor for a password reset.
    // Require a valid, unexpired, single-use token that was delivered to the
    // account's registered email address before allowing the password change.
    const storedToken = resetTokens.get(email)
    if (!storedToken || storedToken.expires < Date.now() || typeof token !== 'string' || !tokensMatch(storedToken.token, token)) {
      resetTokens.delete(email)
      res.status(401).send(res.__('Invalid or expired password reset token.'))
      return
    }
    try {
      const data = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if ((data != null) && security.hmac(answer) === data.answer) {
        const user = await UserModel.findByPk(data.UserId)
        if (user) {
          const updatedUser = await user.update({ password: newPassword })
          resetTokens.delete(email) // one-time use: invalidate the token after a successful reset
          verifySecurityAnswerChallenges(updatedUser, answer)
          res.json({ user: updatedUser })
        }
      } else {
        res.status(401).send(res.__('Wrong answer to security question.'))
      }
    } catch (error) {
      next(error)
    }
  }
}

function verifySecurityAnswerChallenges (user: UserModel, answer: string) {
  challengeUtils.solveIf(challenges.resetPasswordJimChallenge, () => { return user.id === users.jim.id && answer === 'Samuel' })
  challengeUtils.solveIf(challenges.resetPasswordBenderChallenge, () => { return user.id === users.bender.id && answer === 'Stop\'n\'Drop' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernChallenge, () => { return user.id === users.bjoern.id && answer === 'West-2082' })
  challengeUtils.solveIf(challenges.resetPasswordMortyChallenge, () => { return user.id === users.morty.id && answer === '5N0wb41L' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernOwaspChallenge, () => { return user.id === users.bjoernOwasp.id && answer === 'Zaya' })
  challengeUtils.solveIf(challenges.resetPasswordUvoginChallenge, () => { return user.id === users.uvogin.id && answer === 'Silence of the Lambs' })
  challengeUtils.solveIf(challenges.geoStalkingMetaChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingMetaSecurityAnswer) {
          return memories[i].geoStalkingMetaSecurityAnswer
        }
      }
    })())
    return user.id === users.john.id && answer === securityAnswer
  })
  challengeUtils.solveIf(challenges.geoStalkingVisualChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingVisualSecurityAnswer) {
          return memories[i].geoStalkingVisualSecurityAnswer
        }
      }
    })())
    return user.id === users.emma.id && answer === securityAnswer
  })
}
