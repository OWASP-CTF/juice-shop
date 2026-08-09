/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ChallengeModel } from '../models/challenge'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { Op } from 'sequelize'

export function continueCode () {
  return (req: Request, res: Response) => {
    const ids = []
    for (const challenge of Object.values(challenges)) {
      if (challenge.solved) ids.push(challenge.id)
    }
    const continueCode = ids.length > 0 ? security.encodeProgress('progress', ids) : undefined
    res.json({ continueCode })
  }
}

export function continueCodeFindIt () {
  return async (req: Request, res: Response) => {
    const ids = []
    const challenges = await ChallengeModel.findAll({ where: { codingChallengeStatus: { [Op.gte]: 1 } } })
    for (const challenge of challenges) {
      ids.push(challenge.id)
    }
    const continueCode = ids.length > 0 ? security.encodeProgress('findIt', ids) : undefined
    res.json({ continueCode })
  }
}

export function continueCodeFixIt () {
  return async (req: Request, res: Response) => {
    const ids = []
    const challenges = await ChallengeModel.findAll({ where: { codingChallengeStatus: { [Op.gte]: 2 } } })
    for (const challenge of challenges) {
      ids.push(challenge.id)
    }
    const continueCode = ids.length > 0 ? security.encodeProgress('fixIt', ids) : undefined
    res.json({ continueCode })
  }
}
