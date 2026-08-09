/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

// The only attributes this endpoint is ever allowed to disclose. `fields` selects a
// subset of these; it can never be used to project other columns of the user record.
const SELECTABLE_FIELDS = ['id', 'email', 'lastLoginIp', 'profileImage'] as const

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        // Parse the fields parameter into an array, splitting by comma, and keep only
        // the attributes that are safe to expose.
        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam
          ? fieldsParam.split(',').map(f => f.trim()).filter((f): f is typeof SELECTABLE_FIELDS[number] => (SELECTABLE_FIELDS as readonly string[]).includes(f))
          : []

        let baseUser: any = {}

        if (requestedFields.length > 0) {
          // When fields are specified, return only those fields
          for (const field of requestedFields) {
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
            profileImage: user?.data?.profileImage
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
