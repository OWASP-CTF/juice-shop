/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import Hashids from 'hashids/cjs'
import { continueCodeSalt, findItSalt, fixItSalt } from '../lib/continueCodeSecrets'
import { type Request, type Response } from 'express'
import { ChallengeModel } from '../models/challenge'
import { challenges } from '../data/datacache'
import { Op } from 'sequelize'

export function continueCode () {
  const hashids = new Hashids(continueCodeSalt, 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
  return (req: Request, res: Response) => {
    const ids = []
    for (const challenge of Object.values(challenges)) {
      if (challenge.solved) ids.push(challenge.id)
    }
    const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined
    res.json({ continueCode })
  }
}

export function continueCodeFindIt () {
  const hashids = new Hashids(findItSalt, 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
  return async (req: Request, res: Response) => {
    const ids = []
    const challenges = await ChallengeModel.findAll({ where: { codingChallengeStatus: { [Op.gte]: 1 } } })
    for (const challenge of challenges) {
      ids.push(challenge.id)
    }
    const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined
    res.json({ continueCode })
  }
}

export function continueCodeFixIt () {
  const hashids = new Hashids(fixItSalt, 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
  return async (req: Request, res: Response) => {
    const ids = []
    const challenges = await ChallengeModel.findAll({ where: { codingChallengeStatus: { [Op.gte]: 2 } } })
    for (const challenge of challenges) {
      ids.push(challenge.id)
    }
    const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined
    res.json({ continueCode })
  }
}
