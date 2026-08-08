/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return (_req: Request, res: Response, _next: NextFunction) => {
    res.status(404).end()
  }
}
