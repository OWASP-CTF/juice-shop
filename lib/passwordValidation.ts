/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const COMMON_PASSWORDS = new Set([
  'admin123',
  'password',
  '123456',
  '123456789',
  '12345678',
  '12345',
  'qwerty',
  'abc123',
  'password1',
  '111111',
  '123123',
  'admin',
  'letmein',
  'welcome',
  'monkey',
  'dragon',
  'master',
  'login',
  'princess',
  'football'
])

export function validatePasswordHasAtLeastTenChar (password: string) {
  if (password.length < 10) {
    throw new Error('Password must be at least 10 characters long.')
  }
}

export function validatePasswordIsNotInTopOneMillionCommonPasswordsList (password: string) {
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    throw new Error('Password is too common.')
  }
}
