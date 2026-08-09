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
    /* The photo wall is readable without signing in, and pulling in the whole associated user
       row shipped every uploader's email address, password hash, TOTP secret and deluxe token
       along with the picture. The wall only ever renders who posted a memory, so that single
       column is the only one that leaves the database. */
    const memories = await MemoryModel.findAll({ include: [{ model: UserModel, attributes: ['username'] }] })
    res.status(200).json({ status: 'success', data: memories })
  }
}
