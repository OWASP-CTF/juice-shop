/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns/promises'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// Blocks the classic SSRF targets: loopback, RFC1918 private ranges, link-local (which
// includes the 169.254.169.254 cloud metadata endpoint), and their IPv6 equivalents.
function isForbiddenAddress (address: string): boolean {
  if (net.isIP(address) === 4) {
    const octets = address.split('.').map(Number)
    const [a, b] = octets
    return a === 127 || a === 10 || a === 0 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
  }
  if (net.isIP(address) === 6) {
    const normalized = address.toLowerCase()
    return normalized === '::1' ||
      normalized.startsWith('fe80:') ||
      normalized.startsWith('fc') || normalized.startsWith('fd') ||
      normalized.startsWith('::ffff:127.') ||
      normalized.startsWith('::ffff:10.') ||
      normalized.startsWith('::ffff:169.254.')
  }
  return true // not a resolvable IP at all - reject rather than risk fetching it
}

async function isSsrfSafeUrl (rawUrl: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }
  try {
    const addresses = net.isIP(parsed.hostname)
      ? [parsed.hostname]
      : (await dns.lookup(parsed.hostname, { all: true })).map(a => a.address)
    if (addresses.length === 0) return false
    return addresses.every(address => !isForbiddenAddress(address))
  } catch {
    return false
  }
}

// fetch() follows redirects transparently by default - validating only the URL the caller
// supplied and then letting fetch() itself chase a 3xx response would let an attacker point at
// an allowed public host that redirects to an internal address, bypassing the check entirely.
// Re-validate (and re-resolve) every hop before following it.
async function ssrfSafeFetch (url: string, maxRedirects = 5): Promise<globalThis.Response> {
  let currentUrl = url
  for (let i = 0; i <= maxRedirects; i++) {
    if (!(await isSsrfSafeUrl(currentUrl))) {
      throw new Error('URL is not allowed (must be a public http(s) address)')
    }
    const response = await fetch(currentUrl, { redirect: 'manual' })
    const location = response.headers.get('location')
    if (response.status >= 300 && response.status < 400 && location) {
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return response
  }
  throw new Error('Too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          // The URL was previously fetched with no validation at all, letting an attacker
          // make the server issue requests to internal services or the cloud metadata
          // endpoint (169.254.169.254) using the app's own network position.
          const response = await ssrfSafeFetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
