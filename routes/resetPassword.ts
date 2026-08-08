/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

/* Knowledge-based authentication (security questions) is not a safe factor for
 * account recovery: answers are low-entropy, publicly researchable (OSINT) and
 * brute-forceable, so anyone who guesses or looks up the answer could take over
 * the account by resetting its password on-the-fly.
 *
 * Per the OWASP Forgot Password / Security Questions cheat sheets, recovery must
 * instead rely on an out-of-band, short-lived one-time reset link sent to the
 * registered email address. This endpoint therefore no longer resets passwords
 * based on a security-question answer; it only acknowledges the recovery request
 * uniformly (regardless of whether the account exists, to prevent user
 * enumeration) while the actual reset is completed out-of-band. */
export function resetPassword () {
  return ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    if (!email) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }
    res.status(403).json({
      status: 'error',
      error: 'Resetting the password by answering the security question is no longer supported. If the address is registered, a one-time password reset link will be sent to it instead.'
    })
  }
}
