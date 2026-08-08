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
    /* The owner used to be taken from the request body, so a memory could be
       filed under any account. It is now always the authenticated caller. */
    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser?.data?.id) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const record = {
      caption: req.body.caption,
      imagePath: 'assets/public/images/uploads/' + req.file?.filename,
      UserId: loggedInUser.data.id
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
