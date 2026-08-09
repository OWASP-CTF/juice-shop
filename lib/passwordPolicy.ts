/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* A password only protects an account for as long as guessing it is expensive. Length is what
   makes it expensive, and being absent from the lists an attacker already owns is what stops the
   first thousand guesses from working. Both are checked wherever a customer chooses a password. */

const MINIMUM_LENGTH = 10

/* The head of every credential list in circulation, plus the shop-flavoured variants that show up
   in them. A deployment should point this at a full breach corpus; the point of the list is that
   membership, not shape, is what disqualifies a password. */
const wellKnownPasswords = new Set([
  '123456', '123456789', '12345678', '1234567890', '1234567', 'password', 'password1', 'password123',
  'qwerty', 'qwerty123', 'qwertyuiop', 'admin', 'admin123', 'administrator', 'root', 'toor',
  'letmein', 'welcome', 'welcome1', 'monkey', 'dragon', 'sunshine', 'iloveyou', 'princess',
  'football', 'baseball', 'superman', 'batman', 'trustno1', 'abc123', 'abcd1234', 'a1b2c3d4',
  'passw0rd', 'p@ssw0rd', 'p@ssword', 'secret', 'changeme', 'default', 'test1234', 'juiceshop',
  'juice-shop', 'juicyjuice', 'orangejuice', 'ncc-1701', '0000000000', '1111111111', 'aaaaaaaaaa'
])

export const passwordPolicyViolation = (password: string, email?: string): string | undefined => {
  if (typeof password !== 'string' || password.length < MINIMUM_LENGTH) {
    return `Password must be at least ${MINIMUM_LENGTH} characters long.`
  }
  const normalized = password.trim().toLowerCase()
  if (wellKnownPasswords.has(normalized)) {
    return 'Password is among the most commonly used passwords and must not be used.'
  }
  if (/^(.)\1+$/.test(normalized)) {
    return 'Password must not consist of a single repeated character.'
  }
  const localPart = typeof email === 'string' ? email.split('@')[0].toLowerCase() : ''
  if (localPart.length > 2 && normalized.includes(localPart)) {
    return 'Password must not contain the account name.'
  }
  return undefined
}
