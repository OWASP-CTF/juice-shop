/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const LOG_DIRECTORY = path.resolve('logs')

// Support staff still need to read the logs, so the endpoint stays. What changes is that
// the caller must be an administrator (enforced where this is mounted) and that the
// resolved path is proven to sit inside logs/ rather than merely lacking a slash — a
// segment such as '..%2f' arrives decoded and a bare name check would not catch it.
const isContainedLogFile = (file: string) => {
  if (!/^[\w.-]+$/.test(file) || file.includes('..')) {
    return false
  }
  const resolved = path.resolve(LOG_DIRECTORY, file)
  return (resolved === LOG_DIRECTORY || resolved.startsWith(LOG_DIRECTORY + path.sep)) &&
    /\.log(\.[\d-]+)?$/.test(resolved)
}

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (isContainedLogFile(file)) {
      res.sendFile(path.resolve(LOG_DIRECTORY, file))
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
