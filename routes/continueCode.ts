/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response } from 'express'
import { ChallengeModel } from '../models/challenge'
import { challenges } from '../data/datacache'
import { Op } from 'sequelize'
import * as security from '../lib/insecurity'

type ContinueCodeScope = 'solve' | 'find' | 'fix'

export function createContinueCode (ids: number[], scope: ContinueCodeScope): string | undefined {
  const normalizedIds = [...new Set(ids)].filter(id => Number.isSafeInteger(id) && id > 0)
  if (normalizedIds.length === 0) return undefined
  const payload = Buffer.from(JSON.stringify(normalizedIds)).toString('base64url')
  const signature = security.hmac(`continue-code:${scope}:${payload}`)
  return `${payload}.${signature}`
}

export function decodeContinueCode (continueCode: string, scope: ContinueCodeScope): number[] | undefined {
  const match = /^([A-Za-z0-9_-]+)\.([a-f0-9]{64})$/.exec(continueCode)
  if (!match) return undefined
  const [, payload, signature] = match
  const expected = security.hmac(`continue-code:${scope}:${payload}`)
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return undefined
  try {
    const ids: unknown = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
    if (!Array.isArray(ids) || ids.length === 0 || !ids.every(id => Number.isSafeInteger(id) && id > 0)) return undefined
    return [...new Set(ids)] as number[]
  } catch {
    return undefined
  }
}

export function continueCode () {
  return (req: Request, res: Response) => {
    const ids = []
    for (const challenge of Object.values(challenges)) {
      if (challenge.solved) ids.push(challenge.id)
    }
    const continueCode = createContinueCode(ids, 'solve')
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
    const continueCode = createContinueCode(ids, 'find')
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
    const continueCode = createContinueCode(ids, 'fix')
    res.json({ continueCode })
  }
}
