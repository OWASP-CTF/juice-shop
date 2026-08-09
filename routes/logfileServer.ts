/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Confine the resolved path to the log directory; filtering the raw name leaves every
    // traversal form that resolve() understands.
    const logDirectory = path.resolve('logs')
    const resolved = path.resolve(logDirectory, file)

    if (resolved.startsWith(logDirectory + path.sep)) {
      res.sendFile(resolved)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
