/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const logDirectory = path.resolve('logs')
    const resolvedPath = path.resolve(logDirectory, file)

    // Confine the resolved path to the log directory instead of just rejecting a literal
    // forward slash in the file name - that alone does not stop path traversal via encoded
    // separators or other means of escaping the intended directory.
    if (resolvedPath.startsWith(logDirectory + path.sep)) {
      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
