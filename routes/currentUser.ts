/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'

const publicUserFields = new Set(['id', 'email', 'lastLoginIp', 'profileImage'])

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []

        const safeUser: Record<string, string | number | undefined> = {
          id: user?.data?.id,
          email: user?.data?.email,
          lastLoginIp: user?.data?.lastLoginIp,
          profileImage: user?.data?.profileImage
        }
        let baseUser: Record<string, string | number | undefined> = {}

        if (requestedFields.length > 0) {
          for (const field of requestedFields) {
            if (publicUserFields.has(field)) {
              baseUser[field] = safeUser[field]
            }
          }
        } else {
          baseUser = safeUser
        }

        response = { user: baseUser }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }
    res.json(response)
  }
}
