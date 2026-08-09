/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export const REDACTION = '[redacted]'

/* Candidate BIP-39 recovery phrases: 12, 15, 18, 21 or 24 lowercase words in a row. */
const CANDIDATE_PHRASE = /\b[a-z]{3,8}(?:[ \t]+[a-z]{3,8}){11,23}\b/g

let isValidMnemonic: ((phrase: string) => boolean) | null = null
void import('ethers')
  .then(({ Mnemonic }) => {
    isValidMnemonic = (phrase: string) => Mnemonic.isValidMnemonic(phrase)
  })
  .catch(() => {
    /* Without the wordlist we cannot tell a recovery phrase from prose, so we redact every candidate. */
  })

function isRecoveryPhrase (candidate: string): boolean {
  if (isValidMnemonic === null) return true
  const words = candidate.split(/[ \t]+/)
  for (let length = 24; length >= 12; length -= 3) {
    for (let start = 0; start + length <= words.length; start++) {
      if (isValidMnemonic(words.slice(start, start + length).join(' '))) return true
    }
  }
  return false
}

export function redactRecoveryPhrases (text: string): string {
  return text.replace(CANDIDATE_PHRASE, (match) => (isRecoveryPhrase(match) ? REDACTION : match))
}

/* Redacts on the serialized payload so that the response keeps its exact shape. */
function redactPayload (body: unknown): unknown {
  const serialized = JSON.stringify(body)
  if (serialized === undefined) return body
  const redacted = redactRecoveryPhrases(serialized)
  return redacted === serialized ? body : JSON.parse(redacted)
}

/**
 * Customer-authored content is echoed back to anyone who can read it. A wallet recovery phrase
 * pasted into such content is a credential, not a comment, so it must never leave the server.
 */
export function redactWalletSecrets () {
  return (req: Request, res: Response, next: NextFunction) => {
    const json = res.json.bind(res)
    res.json = (body: unknown) => json(redactPayload(body))
    next()
  }
}
