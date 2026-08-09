/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file === 'jwt.pub') {
      /* A verification key is public by design, but no other file from the key
         directory is remotely retrievable. */
      res.type('text/plain').send(security.publicKey)
    } else {
      res.status(404)
      next(new Error('Key not found'))
    }
  }
}
