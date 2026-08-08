/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import path from 'node:path'

const ftpRoot = path.resolve('ftp')
const publicFilePattern = /^(?:legal\.md|order_[a-f\d]{4}-[a-f\d]{16}\.pdf)$/i

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file || /[\\/\0]/.test(file) || !publicFilePattern.test(file)) {
      res.status(403)
      next(new Error('File is not publicly accessible.'))
      return
    }

    const filePath = path.resolve(ftpRoot, file)
    if (!filePath.startsWith(ftpRoot + path.sep)) {
      res.status(403)
      next(new Error('File is not publicly accessible.'))
      return
    }
    res.sendFile(filePath)
  }
}
