/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { decodeContinueCode } from './continueCode'

const invalidContinueCode = 'Invalid continue code.'

function validChallengeIds (ids: number[] | undefined): ids is number[] {
  const knownIds = new Set(Object.values(challenges).map(challenge => challenge.id))
  return ids !== undefined && ids.every(id => knownIds.has(id))
}

export function restoreProgress () {
  return ({ params }: Request, res: Response) => {
    const ids = decodeContinueCode(params.continueCode, 'solve')
    if (validChallengeIds(ids)) {
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
    const idsFindIt = decodeContinueCode(params.continueCode, 'find')
    if (validChallengeIds(idsFindIt)) {
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
    const idsFixIt = decodeContinueCode(params.continueCode, 'fix')
    if (validChallengeIds(idsFixIt)) {
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
