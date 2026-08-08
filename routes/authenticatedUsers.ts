/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { decode } from 'jsonwebtoken'
import * as security from '../lib/insecurity'

async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  try {
    const currentUser = security.authenticatedUsers.from(req)
    if (currentUser?.data?.role !== security.roles.admin) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }

    const users = await UserModel.findAll({
      attributes: ['id', 'username', 'email', 'role', 'profileImage', 'lastLoginIp', 'isActive']
    })

    res.json({
      status: 'success',
      data: users.map((user) => {
        const userToken = security.authenticatedUsers.tokenOf(user)
        let lastLoginTime: number | null = null
        if (userToken) {
          const parsedToken = decode(userToken, { json: true })
          lastLoginTime = parsedToken ? Math.floor(new Date((parsedToken?.iat ?? 0) * 1000).getTime()) : null
        }

        return {
          ...user.dataValues,
          lastLoginTime
        }
      })
    })
  } catch (error) {
    next(error)
  }
}

export default () => retrieveUserList
