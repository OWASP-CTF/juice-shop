/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

// Only the JWT verification key is meant to be public here. Everything else in
// this directory - the premium content key in particular - was downloadable by
// anyone who guessed or browsed to the name.
const publiclyServableKeys = new Set(['jwt.pub'])

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }
    if (!publiclyServableKeys.has(file)) {
      res.status(403).json({ error: 'Access to this key file is forbidden!' })
      return
    }
    // Serve the key actually in use rather than the copy on disk, which is
    // stale now that the pair is supplied by the environment or generated.
    res.type('text/plain').send(security.publicKey)
  }
}
