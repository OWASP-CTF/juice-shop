/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const file = req.params.file

      if (
        typeof file !== 'string' ||
        file.length === 0 ||
        file !== path.basename(file) ||
        file.includes('/') ||
        file.includes('\\') ||
        file.includes('..')
      ) {
        res.status(400).json({
          error: 'Invalid log file name'
        })
        return
      }

      /*
       * Only actual rotated access-log files may be served.
       * Example: access.log.2026-08-07
       */
      if (!/^access\.log\.\d{4}-\d{2}-\d{2}$/.test(file)) {
        res.status(404).json({
          error: 'Log file not found'
        })
        return
      }

      const logsDirectory = path.resolve('logs')
      const requestedFile = path.resolve(logsDirectory, file)

      /*
       * Defense in depth: ensure the resolved path never escapes
       * the logs directory.
       */
      if (!requestedFile.startsWith(logsDirectory + path.sep)) {
        res.status(403).json({
          error: 'Access denied'
        })
        return
      }

      res.sendFile(requestedFile, (error) => {
        if (error != null) {
          next(error)
        }
      })
    } catch (error) {
      next(error)
    }
  }
}
