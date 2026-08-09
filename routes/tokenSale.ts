/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

/*
 * The token sale is unannounced material. Until now the only thing keeping it out of
 * reach was the obfuscated URL of its page - obscurity, not access control. These helpers
 * put an actual authorization decision in front of everything that belongs to it.
 */

/* Assets that are exclusively part of the unannounced token sale page. */
const TOKEN_SALE_ASSETS = ['/56px.png']

/* Only administrators are allowed to see the token sale before its official announcement. */
export const isTokenSaleAudience = (req: Request) => {
  const token = utils.jwtFrom(req)
  if (!token) {
    return false
  }
  const decodedToken: any = security.verify(token) ? security.decode(token) : null
  return decodedToken?.data?.role === security.roles.admin
}

const requestedPath = (req: Request) => {
  const url = req.originalUrl ?? req.url ?? ''
  return url.split('?')[0].split('#')[0].toLowerCase()
}

const isTokenSaleAsset = (req: Request) => {
  const path = requestedPath(req)
  return TOKEN_SALE_ASSETS.some((asset) => path.endsWith(asset))
}

/*
 * Guards every route that could hand out a token sale asset. It is deliberately mounted
 * globally instead of on a single directory, because the same file name is reachable
 * through several static mounts and each of them would otherwise be an open side door.
 */
export function requireTokenSaleAuthorization () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isTokenSaleAsset(req)) {
      next()
      return
    }
    if (isTokenSaleAudience(req)) {
      next()
      return
    }
    res.status(403).json({ error: 'Access to the token sale is restricted to authorized staff.' })
  }
}
