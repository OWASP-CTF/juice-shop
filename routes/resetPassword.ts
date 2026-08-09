/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'

import type { Memory as MemoryConfig } from '../lib/config.types'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

/* A security answer is a low-entropy, often publicly discoverable secret, so the number of
   guesses that can be made against a single account has to be capped independently of any
   per-source rate limit: an attacker with a list of common pet names would otherwise simply
   work through it. Failures are counted per account and the account stops accepting answers
   for a while once the budget is spent. */
const MAX_FAILED_ANSWERS = 5
const LOCKOUT_DURATION_IN_MS = 15 * 60 * 1000
const failedAnswerAttempts = new Map<string, { failures: number, lockedUntil: number }>()

function isLockedOut (email: string) {
  const attempts = failedAnswerAttempts.get(email)
  return attempts !== undefined && attempts.lockedUntil > Date.now()
}

function registerFailedAttempt (email: string) {
  const attempts = failedAnswerAttempts.get(email) ?? { failures: 0, lockedUntil: 0 }
  attempts.failures += 1
  if (attempts.failures >= MAX_FAILED_ANSWERS) {
    attempts.failures = 0
    attempts.lockedUntil = Date.now() + LOCKOUT_DURATION_IN_MS
  }
  failedAnswerAttempts.set(email, attempts)
}

/* Compares the HMACs of the two answers without leaking, through timing, how much of the
   expected value a guess got right. */
function answerMatches (givenAnswer: string, expectedAnswer: string) {
  const given = Buffer.from(security.hmac(givenAnswer), 'utf8')
  const expected = Buffer.from(expectedAnswer, 'utf8')
  return given.length === expected.length && crypto.timingSafeEqual(given, expected)
}

export function resetPassword () {
  return async ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    const answer = body.answer
    const newPassword = body.new
    const repeatPassword = body.repeat
    if (!email || !answer || typeof email !== 'string' || typeof answer !== 'string') {
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
    if (isLockedOut(email)) {
      res.status(429).send(res.__('Wrong answer to security question.'))
      return
    }
    try {
      const data = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if ((data != null) && answerMatches(answer, data.answer)) {
        const user = await UserModel.findByPk(data.UserId)
        if (user) {
          failedAnswerAttempts.delete(email)
          const updatedUser = await user.update({ password: newPassword })
          verifySecurityAnswerChallenges(updatedUser, answer)
          res.json({ user: updatedUser })
        }
      } else {
        registerFailedAttempt(email)
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
