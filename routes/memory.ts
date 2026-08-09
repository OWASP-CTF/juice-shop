/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'

export function addMemory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const record = {
      caption: req.body.caption,
      imagePath: 'assets/public/images/uploads/' + req.file?.filename,
      UserId: req.body.UserId
    }
    const memory = await MemoryModel.create(record)
    res.status(200).json({ status: 'success', data: memory })
  }
}

export function getMemories () {
  return async (req: Request, res: Response, next: NextFunction) => {
    // This endpoint is unauthenticated. An unrestricted include ships every
    // user column with each memory, including the password hash, totpSecret
    // and deluxeToken.
    const memories = await MemoryModel.findAll({
      include: [{ model: UserModel, attributes: ['id', 'username', 'profileImage'] }]
    })
    res.status(200).json({ status: 'success', data: memories })
  }
}
