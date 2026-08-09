/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

const hashidRegexp = /^[a-zA-Z0-9]+$/
const invalidContinueCode = 'Invalid continue code.'

export function restoreProgress () {
  return ({ params }: Request, res: Response) => {
    const continueCode = params.continueCode
    if (!hashidRegexp.test(continueCode)) {
      return res.status(404).send(invalidContinueCode)
    }
    const ids = security.decodeProgress('progress', continueCode)
    if (challengeUtils.notSolved(challenges.continueCodeChallenge) && ids.includes(999)) {
      challengeUtils.solve(challenges.continueCodeChallenge)
      res.end()
    } else if (ids.length > 0) {
      for (const challenge of Object.values(challenges)) {
        if (ids.includes(challenge.id)) {
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
    const continueCodeFindIt = params.continueCode
    if (!hashidRegexp.test(continueCodeFindIt)) {
      return res.status(404).send(invalidContinueCode)
    }
    const idsFindIt = security.decodeProgress('findIt', continueCodeFindIt)
    if (idsFindIt.length > 0) {
      for (const challenge of Object.values(challenges)) {
        if (idsFindIt.includes(challenge.id)) {
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
  return async ({ params }: Request, res: Response) => {
    const continueCodeFixIt = params.continueCode
    if (!hashidRegexp.test(continueCodeFixIt)) {
      return res.status(404).send(invalidContinueCode)
    }
    const idsFixIt = security.decodeProgress('fixIt', continueCodeFixIt)
    if (idsFixIt.length > 0) {
      for (const challenge of Object.values(challenges)) {
        if (idsFixIt.includes(challenge.id)) {
          await challengeUtils.solveFixIt(challenge.key, true)
        }
      }
      res.json({ data: idsFixIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}
