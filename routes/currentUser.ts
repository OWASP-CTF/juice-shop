/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

// The only user attributes this endpoint is allowed to disclose. The fields
// parameter may narrow this set, never extend it.
// Shared with the password change, password reset and login-IP routes, which answer with
// a user record too. 'role' is the caller's own, read from the server-side session rather
// than a token the client could have edited, so it gives the routing guards an
// authoritative answer to check instead of an unverified JWT payload.
const DISCLOSABLE_FIELDS = security.DISCLOSABLE_USER_FIELDS

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        // Parse the fields parameter into an array, splitting by comma.
        // If not provided, both these variables will be undefined.
        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []
        const permittedFields = requestedFields.filter(field => DISCLOSABLE_FIELDS.includes(field))

        let baseUser: any = {}

        if (permittedFields.length > 0) {
          // When fields are specified, return only those fields
          for (const field of permittedFields) {
            if (user?.data[field as keyof typeof user.data] !== undefined) {
              baseUser[field] = user?.data[field as keyof typeof user.data]
            }
          }
        } else {
          // If no fields parameter, return standard fields (not password field)
          baseUser = {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage,
            role: user?.data?.role
          }
        }

        response = { user: baseUser }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }
    // Solve passwordHashLeakChallenge when password field is included in response
    challengeUtils.solveIf(challenges.passwordHashLeakChallenge, () => response?.user?.password)

    if (req.query.callback === undefined) {
      res.json(response)
    } else {
      challengeUtils.solveIf(challenges.emailLeakChallenge, () => { return true })
      res.jsonp(response)
    }
  }
}
