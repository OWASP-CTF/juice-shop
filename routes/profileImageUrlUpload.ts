/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// The upper byte of the octet pairs below is the second dotted-decimal group of an
// IPv4 address; the ranges are the ones with no business being fetched on behalf of
// a remote user: loopback, "this" network, RFC 1918 private space, link-local space
// (which is also where cloud providers hand out instance metadata, e.g.
// 169.254.169.254) and the multicast/reserved space above it.
function isDisallowedIPv4 (firstOctet: number, secondOctet: number): boolean {
  if (firstOctet === 127 || firstOctet === 0) return true
  if (firstOctet === 10) return true
  if (firstOctet === 172 && secondOctet >= 16 && secondOctet <= 31) return true
  if (firstOctet === 192 && secondOctet === 168) return true
  if (firstOctet === 169 && secondOctet === 254) return true
  if (firstOctet >= 224) return true
  return false
}

// Turns a normalized IPv6 literal's last 32 bits into the two decimal octet pairs
// they represent, so an IPv4-mapped address (e.g. ::ffff:7f00:1 for 127.0.0.1)
// can be run through the same IPv4 range check instead of being waved through.
function trailingIPv4OfMappedAddress (v6: string): [number, number] | null {
  const groups = v6.split(':')
  if (groups.length < 2 || !v6.includes('ffff')) return null
  const last = groups[groups.length - 1]
  const secondToLast = groups[groups.length - 2]
  if (!/^[0-9a-f]{1,4}$/i.test(last) || !/^[0-9a-f]{1,4}$/i.test(secondToLast)) return null
  const high = parseInt(secondToLast.padStart(4, '0'), 16)
  return [(high >> 8) & 0xff, high & 0xff]
}

// The imageUrl feature has this server fetch a URL on a logged-in user's behalf.
// Without a check here, a hostname or IP literal that actually points back at this
// very deployment turns "grab my avatar" into the server attacking itself. This
// looks only at the literal address the caller supplied (no DNS lookups, no probing
// of our own network interfaces) and rejects anything that could resolve to
// ourselves or to infrastructure that should only ever be reachable from inside the
// deployment. See the OWASP SSRF Prevention Cheat Sheet linked from this challenge.
function isSelfOrInternalTarget (rawUrl: string): boolean {
  let target: URL
  try {
    target = new URL(rawUrl)
  } catch {
    return true // not a well-formed absolute URL - nothing legitimate to fetch here
  }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return true // e.g. file:, data:, gopher: - never a legitimate avatar source
  }

  const host = target.hostname.toLowerCase()

  if (host === 'localhost' || host.endsWith('.localhost')) return true
  if (host === 'metadata' || host === 'metadata.google.internal') return true

  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/)
  if (ipv4 !== null) {
    return isDisallowedIPv4(Number(ipv4[1]), Number(ipv4[2]))
  }

  if (host.startsWith('[') && host.endsWith(']')) {
    const v6 = host.slice(1, -1)
    if (v6 === '::1' || v6 === '::') return true
    if (v6.startsWith('fe80:') || v6.startsWith('fc') || v6.startsWith('fd')) return true
    const mapped = trailingIPv4OfMappedAddress(v6)
    if (mapped !== null) return isDisallowedIPv4(mapped[0], mapped[1])
    return false
  }

  return false
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (isSelfOrInternalTarget(url)) {
            throw new Error('refusing to fetch a URL that targets this deployment or its internal network')
          }
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
