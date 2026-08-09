/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'

import * as security from './insecurity'

/* Brute-force protection for the security-question password reset
   (A07:2025 Authentication Failures, CWE-307).

   The per-IP rate limit in server.ts is not enough on its own: an attacker with
   a pool of addresses can still walk a list of common pet names. Counting the
   failures per account instead means rotating the source address buys nothing. */

const MAX_FAILED_ATTEMPTS = 5
const LOCKOUT_DURATION_MS = 15 * 60 * 1000

interface AttemptRecord {
  readonly failures: number
  readonly lockedUntil: number
}

const attemptsByEmail = new Map<string, AttemptRecord>()

const keyFor = (email: string): string => email.trim().toLowerCase()

export const isLockedOut = (email: string): boolean => {
  const key = keyFor(email)
  const record = attemptsByEmail.get(key)
  if (!record) {
    return false
  }
  if (record.lockedUntil === 0) {
    /* Still below the threshold, so keep the running count. */
    return false
  }
  if (record.lockedUntil > Date.now()) {
    return true
  }
  /* The lockout has been served, so the account starts over with a clean slate. */
  attemptsByEmail.delete(key)
  return false
}

export const recordFailedAttempt = (email: string): void => {
  const key = keyFor(email)
  const failures = (attemptsByEmail.get(key)?.failures ?? 0) + 1
  attemptsByEmail.set(key, {
    failures,
    lockedUntil: failures >= MAX_FAILED_ATTEMPTS ? Date.now() + LOCKOUT_DURATION_MS : 0
  })
}

export const clearFailedAttempts = (email: string): void => {
  attemptsByEmail.delete(keyFor(email))
}

/* Compares in constant time so the response latency cannot leak how much of the
   stored digest a guess got right (CWE-208). */
export const answerMatches = (answer: string, storedAnswer: string): boolean => {
  const given = Buffer.from(security.hmac(answer), 'hex')
  const stored = Buffer.from(storedAnswer ?? '', 'hex')
  if (given.length !== stored.length) {
    return false
  }
  return crypto.timingSafeEqual(given, stored)
}
