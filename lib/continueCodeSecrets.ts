/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { randomBytes } from 'node:crypto'

/* The salts the continue codes are built from used to be three string literals in the source.
   Hashids is an encoding, not a signature: given the salt anyone can run it in the other
   direction, so a published salt means anyone can mint a code that names whichever challenge
   identifiers they like and have the server accept it as their own recorded progress.
   Keeping the salt out of the repository is what makes the code unforgeable -- it is drawn once,
   at boot, from the system CSPRNG, and the encode and decode sides share it because they are the
   same running process. Codes do not survive a restart, which is the correct lifetime for a value
   the server has no other way of authenticating. */
const mintSalt = () => randomBytes(32).toString('hex')

export const continueCodeSalt = mintSalt()
export const findItSalt = mintSalt()
export const fixItSalt = mintSalt()
