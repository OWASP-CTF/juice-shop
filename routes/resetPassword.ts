/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'

import type { Memory as MemoryConfig } from '../lib/config.types'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import { answerMatches, clearFailedAttempts, isLockedOut, recordFailedAttempt } from '../lib/passwordResetGuard'
import { issueResetToken, redeemResetToken } from '../lib/passwordResetToken'
import logger from '../lib/logger'
import { UserModel } from '../models/user'

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
    /* Too many wrong answers for this account, so stop answering at all for a
       while. Checked per account rather than per IP, otherwise an attacker just
       rotates addresses to brute force the security answer. */
    if (isLockedOut(email)) {
      res.status(429).send(res.__('Too many failed attempts. Please try again later.'))
      return
    }
    try {
      const data = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if ((data == null) || !answerMatches(answer, data.answer)) {
        /* Unknown addresses are counted too, so that the lockout behaviour
           cannot be used to tell existing accounts from non-existing ones. */
        recordFailedAttempt(email)
        res.status(401).send(res.__('Wrong answer to security question.'))
        return
      }
      clearFailedAttempts(email)
      /* Step 1. A security question is researchable, so answering one only
         requests a reset - it never performs one. The one-time token goes out of
         band to the registered address and deliberately never appears in this
         response, which is what stops someone who merely knows the answer. */
      if (!token) {
        const issuedToken = issueResetToken(email)
        /* Stands in for the mail transport this application does not have. A live
           credential must never reach the logs of a real deployment (CWE-532), so
           printing it is opt-in and the default only records that a token was issued. */
        if (process.env.PASSWORD_RESET_TOKEN_TO_LOG === 'true') {
          logger.warn(`Password reset token for ${email}: ${issuedToken} (PASSWORD_RESET_TOKEN_TO_LOG is enabled - never do this outside local development)`)
        } else {
          logger.info(`Password reset token issued for ${email}`)
        }
        res.status(202).json({ status: res.__('A one-time password reset link has been sent to the registered email address.') })
        return
      }
      /* Step 2. Both factors are required here: the answer above and the token. */
      if (!redeemResetToken(email, token)) {
        res.status(401).send(res.__('Invalid or expired password reset token.'))
        return
      }
      const user = await UserModel.findByPk(data.UserId)
      if (user) {
        const updatedUser = await user.update({ password: newPassword })
        verifySecurityAnswerChallenges(updatedUser, answer)
        res.json({ user: updatedUser })
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
