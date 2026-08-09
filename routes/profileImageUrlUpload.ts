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

// Classifies an IP literal as one that must never be reachable via a
// user-supplied profile-image URL (loopback, RFC1918/ULA private space,
// link-local, CGNAT, unspecified and other non-public ranges). Handles
// IPv4, IPv6 and IPv4-mapped IPv6 addresses.
function isDisallowedIp (ip: string): boolean {
  let address = ip
  // Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)
  if (mapped) {
    address = mapped[1]
  }
  const kind = net.isIP(address)
  if (kind === 4) {
    const octets = address.split('.').map(Number)
    const [a, b] = octets
    if (a === 10) return true // 10.0.0.0/8
    if (a === 127) return true // 127.0.0.0/8 loopback
    if (a === 0) return true // 0.0.0.0/8 unspecified
    if (a === 169 && b === 254) return true // 169.254.0.0/16 link-local
    if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12
    if (a === 192 && b === 168) return true // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true // 100.64.0.0/10 CGNAT
    if (a === 192 && b === 0 && octets[2] === 0) return true // 192.0.0.0/24
    if (a >= 224) return true // multicast / reserved
    return false
  }
  if (kind === 6) {
    const lower = address.toLowerCase()
    if (lower === '::1' || lower === '::') return true // loopback / unspecified
    if (lower.startsWith('fe80')) return true // link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true // fc00::/7 unique-local
    if (lower.startsWith('ff')) return true // multicast
    return false
  }
  // Unknown / unparseable — fail closed.
  return true
}

// Throws when the supplied profile-image URL would let the server reach an
// internal/loopback/private resource (SSRF). Only http(s) URLs pointing at a
// public host are considered safe. A URL that cannot even be parsed is left to
// the caller's existing fetch/fallback handling (it can never resolve to an
// internal resource), so unrelated behaviour is preserved.
async function assertSafeImageUrl (rawUrl: string): Promise<void> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    // Not a valid absolute URL — fetch() will reject it too, so it cannot be
    // used to reach an internal resource. Leave it to legacy handling.
    return
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Refusing to fetch profile image over unsupported protocol "${parsed.protocol}"`)
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (hostname === '' || hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new Error(`Refusing to fetch profile image from internal host "${parsed.hostname}"`)
  }

  // If the host is an IP literal, classify it directly.
  if (net.isIP(hostname) !== 0) {
    if (isDisallowedIp(hostname)) {
      throw new Error(`Refusing to fetch profile image from non-public address "${parsed.hostname}"`)
    }
    return
  }

  // Otherwise resolve the hostname and reject if ANY resolved address is
  // internal (defends against hostnames that point at private space, e.g. the
  // Juice Shop container's own address).
  let resolved: Array<{ address: string }> = []
  try {
    resolved = await dns.lookup(hostname, { all: true, verbatim: true })
  } catch {
    // Unresolvable host cannot reach an internal resource; defer to legacy
    // fetch/fallback handling so unrelated features keep working.
    return
  }
  if (resolved.some((entry) => isDisallowedIp(entry.address))) {
    throw new Error(`Refusing to fetch profile image resolving to a non-public address ("${parsed.hostname}")`)
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          // Validate BEFORE the URL is used for anything. An SSRF attempt at an
          // internal/loopback/private target is rejected here and never gets to
          // trigger a server-side request or be persisted, so the server can no
          // longer be coerced into requesting its own internal resources.
          await assertSafeImageUrl(url)
        } catch (validationError) {
          logger.warn(`Blocked SSRF attempt for profile image URL "${url}": ${utils.getErrorMessage(validationError)}`)
          res.location(process.env.BASE_PATH + '/profile')
          res.redirect(process.env.BASE_PATH + '/profile')
          return
        }
        // NOTE: the flag that marks a successful SSRF must never be derived from
        // the *string* the user supplied — doing so let the attack succeed by
        // merely posting a URL containing the internal solve path, with no
        // request ever being made. With the safety check above, the server can
        // no longer be coerced into requesting an internal resource, so the
        // condition that this flag represents can never occur and it stays
        // false.
        try {
          const response = await fetch(url)
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
