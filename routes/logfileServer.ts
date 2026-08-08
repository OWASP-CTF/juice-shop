/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file ?? ''
    const logDirectory = path.resolve('logs')
    const requested = path.resolve(logDirectory, file)

    // Access logs record tokens, session identifiers and customer data, so the
    // log directory is not published. Path traversal is rejected as well.
    if (!requested.startsWith(logDirectory + path.sep)) {
      res.status(403)
      next(new Error('Invalid log file name!'))
      return
    }
    res.status(403)
    next(new Error('Access to application log files is not permitted.'))
  }
}
