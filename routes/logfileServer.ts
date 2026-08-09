/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const logsDirectory = path.resolve('logs')

/* Server access logs contain session tokens, IPs and internal URLs, so they are
   only ever handed out to an authenticated administrator. */
function isAuthenticatedAdmin (req: Request) {
  const token = utils.jwtFrom(req) || req.cookies?.token
  if (!token) {
    return false
  }
  const decodedToken = security.verify(token) && security.decode(token)
  return decodedToken?.data?.role === security.roles.admin
}

export function serveLogFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isAuthenticatedAdmin(req)) {
      res.status(403).json({ error: 'Server access logs are only available to authenticated administrators' })
      return
    }

    const file = security.cutOffPoisonNullByte(req.params.file)

    if (file.includes('/') || file.includes('\\') || file.includes('..')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    /* Containment check: whatever the parameter was, the resolved path has to
       stay a direct child of the logs directory. */
    const resolvedPath = path.resolve(logsDirectory, path.basename(file))
    if (path.dirname(resolvedPath) !== logsDirectory) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    res.sendFile(resolvedPath)
  }
}
