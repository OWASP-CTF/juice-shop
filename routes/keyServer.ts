/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Refusing a forward slash says nothing about what the name resolves to, and the
    // directory holds more than the one key that is meant to be public. The verification
    // key is served from the running process, so it always matches the key in use and no
    // other file in encryptionkeys/ is remotely retrievable.
    if (file === 'jwt.pub') {
      res.type('text/plain').send(security.publicKey)
    } else {
      res.status(404)
      next(new Error('Key not found'))
    }
  }
}
