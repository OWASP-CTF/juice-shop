/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function addMemory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.id) return res.status(401).json({ status: 'error', data: 'Unauthorized' })
    const record = {
      caption: req.body.caption,
      imagePath: 'assets/public/images/uploads/' + req.file?.filename,
      UserId: user.data.id
    }
    const memory = await MemoryModel.create(record)
    res.status(200).json({ status: 'success', data: memory })
  }
}

export function getMemories () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const memories = await MemoryModel.findAll({ include: [UserModel] })
    res.status(200).json({ status: 'success', data: memories })
  }
}
