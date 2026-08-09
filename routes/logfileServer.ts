/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const logsDirectory = path.resolve('logs')

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const resolvedPath = path.resolve(logsDirectory, file)

    // Containment check against the logs directory, so no combination of separators,
    // parent references or absolute paths can reach a file outside of it.
    if (!file.includes('/') && !file.includes('\\') && resolvedPath.startsWith(logsDirectory + path.sep)) {
      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
