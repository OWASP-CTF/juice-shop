/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!isPublicFile(file)) {
      res.status(403).json({ error: 'File is not available' })
      return
    }
    res.sendFile(path.resolve('ftp', file), (error) => {
      if (error) next(error)
    })
  }
}

function isPublicFile (file: unknown): file is string {
  return typeof file === 'string' && (file === 'legal.md' || /^order_[a-f0-9]{4}-[a-f0-9]{16}\.pdf$/.test(file))
}
