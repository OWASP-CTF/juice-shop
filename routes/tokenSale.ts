/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'

/*
 * The token sale has not been announced yet. Its page was kept out of reach by an
 * obfuscated route only - obscurity rather than access control - while everything the
 * page is made of was served to anyone who asked. Until the sale is officially released,
 * nothing that belongs to it is served at all.
 */

/* Assets that exist only as part of the unannounced token sale page. */
const TOKEN_SALE_ASSETS = ['/56px.png']

const requestedPath = (req: Request) => {
  const url = req.originalUrl ?? req.url ?? ''
  return url.split('?')[0].split('#')[0].toLowerCase()
}

const isTokenSaleAsset = (req: Request) => {
  const path = requestedPath(req)
  return TOKEN_SALE_ASSETS.some((asset) => path.endsWith(asset))
}

/*
 * Mounted globally rather than on one directory: the same file name is reachable through
 * several static mounts, and each one of them would otherwise be an open side door.
 */
export function withholdUnreleasedTokenSale () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isTokenSaleAsset(req)) {
      next()
      return
    }
    res.status(404).json({ error: 'Not found' })
  }
}

/* Removes the unreleased altcoin name from a configuration object before it leaves the server. */
export function withoutUnreleasedTokenSale (configuration: any) {
  if (configuration?.application) {
    delete configuration.application.altcoinName
  }
  return configuration
}
