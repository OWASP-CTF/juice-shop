/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'

/* One-time token for the password reset flow
   (A07:2025 Authentication Failures, CWE-640 Weak Password Recovery Mechanism).

   A security question is knowable - Bjoern's pet name is on his YouTube channel -
   so answering one correctly must not be enough on its own to take over an
   account. The answer only *requests* a reset; this token, delivered out of band
   to the registered address, is what authorises it. Rate limiting cannot close
   that gap, because an attacker who already knows the answer never guesses wrong. */

const TOKEN_TTL_MS = 15 * 60 * 1000
const TOKEN_BYTES = 32
const TOKEN_PATTERN = /^[a-f0-9]{64}$/

interface ResetToken {
  readonly token: string
  readonly expiresAt: number
}

const tokensByEmail = new Map<string, ResetToken>()

const keyFor = (email: string): string => email.trim().toLowerCase()

/* Issuing a token invalidates any outstanding one for the same account, so repeated
   reset requests cannot be used to stockpile valid tokens. */
export const issueResetToken = (email: string): string => {
  const token = crypto.randomBytes(TOKEN_BYTES).toString('hex')
  tokensByEmail.set(keyFor(email), { token, expiresAt: Date.now() + TOKEN_TTL_MS })
  return token
}

/* Consumes the token on success, so a leaked link cannot be replayed. */
export const redeemResetToken = (email: string, token: unknown): boolean => {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
    return false
  }
  const key = keyFor(email)
  const record = tokensByEmail.get(key)
  if (!record) {
    return false
  }
  if (record.expiresAt <= Date.now()) {
    tokensByEmail.delete(key)
    return false
  }
  /* Both buffers are 32 bytes because the pattern above fixed the length. */
  if (!crypto.timingSafeEqual(Buffer.from(token, 'hex'), Buffer.from(record.token, 'hex'))) {
    return false
  }
  tokensByEmail.delete(key)
  return true
}
