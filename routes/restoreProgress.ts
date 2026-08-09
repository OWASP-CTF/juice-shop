/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import Hashids from 'hashids/cjs'
import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { continueCodeSalts } from '../lib/insecurity'

const hashidsAlphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
const hashidRegexp = /^[a-zA-Z0-9]+$/
const invalidContinueCode = 'Invalid continue code.'

// Hashids is an obfuscation, not an authenticator: decoding a continue code proves nothing about
// who minted it. The per-process random salts make offline forgery impractical, but decoding must
// not be the only boundary, because /rest/continue-code is an unauthenticated encoder over known
// plaintext (the solved ids are readable from /api/Challenges) and Hashids is documented as
// recoverable from enough such pairs. So the decoded claim is additionally checked against what
// this instance could actually have issued, and a code that fails that check is refused outright
// rather than merely noted. Because the salts are drawn per process, every code this instance ever
// handed out encodes ids of challenges solved in this process, and the solved set only grows within
// a process - so a genuine code always satisfies the check and the restore feature is unaffected.
const decodedIdsOf = (ids: Array<number | bigint>) => ids.map(Number)

const knownChallengeIds = () => {
  const knownIds = new Set<number>()
  for (const challenge of Object.values(challenges)) {
    if (challenge && typeof challenge.id === 'number') {
      knownIds.add(challenge.id)
    }
  }
  return knownIds
}

const solvedChallengeIds = () => {
  const solvedIds = new Set<number>()
  for (const challenge of Object.values(challenges)) {
    if (challenge?.solved && typeof challenge.id === 'number') {
      solvedIds.add(challenge.id)
    }
  }
  return solvedIds
}

const assertsOnlyKnownChallenges = (decodedIds: number[]) => {
  const knownIds = knownChallengeIds()
  return decodedIds.every((id) => Number.isInteger(id) && knownIds.has(id))
}

const assertsOnlyAlreadySolvedChallenges = (decodedIds: number[]) => {
  const solvedIds = solvedChallengeIds()
  return decodedIds.every((id) => Number.isInteger(id) && solvedIds.has(id))
}

export function restoreProgress () {
  return ({ params }: Request, res: Response) => {
    const hashids = new Hashids(continueCodeSalts.challenges, 60, hashidsAlphabet)
    const continueCode = params.continueCode
    if (!hashidRegexp.test(continueCode)) {
      return res.status(404).send(invalidContinueCode)
    }
    const ids = hashids.decode(continueCode)
    const decodedIds = decodedIdsOf(ids)
    // A code asserting an id that is not a challenge at all, or a challenge this instance has not
    // already recorded as solved, is not a code this instance issued. Refuse it instead of letting
    // the restore below mint progress (and with it a CTF flag) for a challenge nobody solved.
    if (!assertsOnlyKnownChallenges(decodedIds) || !assertsOnlyAlreadySolvedChallenges(decodedIds)) {
      return res.status(404).send(invalidContinueCode)
    }
    if (challengeUtils.notSolved(challenges.continueCodeChallenge) && ids.includes(999)) {
      challengeUtils.solve(challenges.continueCodeChallenge)
      res.end()
    } else if (ids.length > 0) {
      for (const challenge of Object.values(challenges)) {
        // Second layer of the same invariant, kept local to the sink: a restore re-asserts progress
        // this instance already granted, it never becomes the thing that first solves a challenge.
        if (decodedIds.includes(challenge.id) && challenge.solved) {
          challengeUtils.solve(challenge, true)
        }
      }
      res.json({ data: ids.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}

export function restoreProgressFindIt () {
  return async ({ params }: Request, res: Response) => {
    const hashids = new Hashids(continueCodeSalts.findIt, 60, hashidsAlphabet)
    const continueCodeFindIt = params.continueCode
    if (!hashidRegexp.test(continueCodeFindIt)) {
      return res.status(404).send(invalidContinueCode)
    }
    const idsFindIt = hashids.decode(continueCodeFindIt)
    const decodedIdsFindIt = decodedIdsOf(idsFindIt)
    if (!assertsOnlyKnownChallenges(decodedIdsFindIt)) {
      return res.status(404).send(invalidContinueCode)
    }
    if (idsFindIt.length > 0) {
      for (const challenge of Object.values(challenges)) {
        if (decodedIdsFindIt.includes(challenge.id)) {
          await challengeUtils.solveFindIt(challenge.key, true)
        }
      }
      res.json({ data: idsFindIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}

export function restoreProgressFixIt () {
  const hashids = new Hashids(continueCodeSalts.fixIt, 60, hashidsAlphabet)
  return async ({ params }: Request, res: Response) => {
    const continueCodeFixIt = params.continueCode
    if (!hashidRegexp.test(continueCodeFixIt)) {
      return res.status(404).send(invalidContinueCode)
    }
    const idsFixIt = hashids.decode(continueCodeFixIt)
    const decodedIdsFixIt = decodedIdsOf(idsFixIt)
    if (!assertsOnlyKnownChallenges(decodedIdsFixIt)) {
      return res.status(404).send(invalidContinueCode)
    }
    if (idsFixIt.length > 0) {
      for (const challenge of Object.values(challenges)) {
        if (decodedIdsFixIt.includes(challenge.id)) {
          await challengeUtils.solveFixIt(challenge.key, true)
        }
      }
      res.json({ data: idsFixIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}
