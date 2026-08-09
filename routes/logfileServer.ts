/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const logDir = path.resolve('logs')
    const requested = path.resolve(logDir, params.file ?? '')

    /* Decide on the resolved destination rather than on the spelling of the name. Screening the
       raw string for a forward slash lets a backslash, a percent-encoded separator or a bare
       ".." walk out of the log directory; a path that resolves back inside logDir cannot. */
    const inside = path.relative(logDir, requested)
    if (inside !== '' && !inside.startsWith('..') && !path.isAbsolute(inside)) {
      res.sendFile(requested)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
