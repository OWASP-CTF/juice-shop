/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// Returns true for loopback, link-local, private (RFC1918/ULA), CGNAT and other
// non-public address ranges that must never be reachable via user-supplied URLs.
function isDisallowedAddress (address: string): boolean {
  const type = net.isIP(address)
  if (type === 4) {
    const [a, b] = address.split('.').map(Number)
    if (a === 0) return true // 0.0.0.0/8 "this host"
    if (a === 127) return true // loopback 127.0.0.0/8
    if (a === 10) return true // RFC1918
    if (a === 172 && b >= 16 && b <= 31) return true // RFC1918
    if (a === 192 && b === 168) return true // RFC1918
    if (a === 169 && b === 254) return true // link-local 169.254.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true // CGNAT RFC6598
    if (a >= 224) return true // multicast/reserved 224.0.0.0/3
    return false
  }
  if (type === 6) {
    const addr = address.toLowerCase()
    if (addr === '::' || addr === '::1') return true // unspecified / loopback
    if (/^fe[89ab]/.test(addr)) return true // link-local fe80::/10
    if (addr.startsWith('fc') || addr.startsWith('fd')) return true // unique local fc00::/7
    // IPv4-mapped IPv6 (::ffff:a.b.c.d): unwrap and re-check the embedded IPv4.
    const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (mapped) return isDisallowedAddress(mapped[1])
    return false
  }
  return true // not a parseable IP literal
}

// Validates a user-supplied image URL to prevent Server-Side Request Forgery.
// Rejects non-http(s) schemes, the application's own origin, and any host
// resolving to an internal address.
async function assertSafeImageUrl (rawUrl: string, ownHost?: string): Promise<void> {
  const parsed = new URL(rawUrl)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Disallowed URL scheme: ${parsed.protocol}`)
  }
  // Reject requests pointing back at the application itself (the SSRF-to-self
  // vector used to reach internal /solve endpoints), regardless of IP range.
  if (ownHost && parsed.host.toLowerCase() === ownHost.toLowerCase()) {
    throw new Error('Disallowed host: application origin')
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  if (hostname.toLowerCase() === 'localhost') {
    throw new Error('Disallowed host: localhost')
  }
  // Literal IP hosts are validated directly; named hosts are resolved so that a
  // DNS record pointing at an internal address cannot bypass the check.
  if (net.isIP(hostname) !== 0) {
    if (isDisallowedAddress(hostname)) {
      throw new Error(`Disallowed host address: ${hostname}`)
    }
  } else {
    const resolved = await dns.lookup(hostname, { all: true })
    if (resolved.length === 0 || resolved.some((entry) => isDisallowedAddress(entry.address))) {
      throw new Error(`Host resolves to a disallowed address: ${hostname}`)
    }
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          // Validate the URL BEFORE issuing any outbound request, blocking SSRF
          // to loopback/link-local/private ranges and the app's own origin.
          await assertSafeImageUrl(url, req.headers.host)
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          // Only a genuinely-performed outbound retrieval counts as abuse — the
          // flag must never be set from unvalidated, attacker-controlled input.
          if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
          const contentType = response.headers.get('content-type') ?? ''
          if (!contentType.toLowerCase().startsWith('image/')) {
            throw new Error(`url returned a non-image content type: ${contentType}`)
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
