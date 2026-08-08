/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      const loggedInUser = security.authenticatedUsers.from(req)
      if (loggedInUser) {
        user = loggedInUser

        // Parse the fields parameter into an array, splitting by comma.
        // If not provided, both these variables will be undefined.
        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []

        const allowedFields = new Set(['id', 'email', 'lastLoginIp', 'profileImage'])
        let baseUser: Record<string, unknown> = {}

        if (requestedFields.length > 0) {
          for (const field of requestedFields) {
            if (allowedFields.has(field) && user?.data[field as keyof typeof user.data] !== undefined) {
              baseUser[field] = user.data[field as keyof typeof user.data]
            }
          }
        } else {
          baseUser = {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage
          }
        }

        res.json({ user: baseUser })
      } else {
        res.json({ user: emptyUser })
      }
    } catch (err) {
      res.json({ user: emptyUser })
    }
  }
}
