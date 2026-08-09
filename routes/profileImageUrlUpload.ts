/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
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

// Classifies a single already-resolved address literal (IPv4 dotted-quad, plain
// IPv6, or an IPv4-mapped IPv6 form) as one that must never be reached on a remote
// user's behalf. This is the one place the range logic above is applied, so both the
// literal-hostname path and the DNS-resolution path below funnel through it.
function isDisallowedAddress (address: string): boolean {
  const a = address.toLowerCase()

  const v4 = a.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/)
  if (v4 !== null) return isDisallowedIPv4(Number(v4[1]), Number(v4[2]))

  if (a === '::1' || a === '::') return true
  if (a.startsWith('fe80') || a.startsWith('fc') || a.startsWith('fd')) return true

  // IPv4-mapped IPv6, either the dotted tail (::ffff:127.0.0.1) or the hex tail
  // (::ffff:7f00:1) - reuse the IPv4 range check on the embedded address.
  if (a.includes('ffff')) {
    const dotted = a.match(/(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/)
    if (dotted !== null) return isDisallowedIPv4(Number(dotted[1]), Number(dotted[2]))
    const mapped = trailingIPv4OfMappedAddress(a)
    if (mapped !== null) return isDisallowedIPv4(mapped[0], mapped[1])
  }

  return false
}

// The imageUrl feature has this server fetch a URL on a logged-in user's behalf.
// Without a check here, a hostname or IP literal that actually points back at this
// very deployment turns "grab my avatar" into the server attacking itself. Beyond the
// obvious IP-literal and internal-name cases, this resolves any real hostname through
// the OS resolver and rejects it if it points at loopback, "this" network, RFC 1918
// private space, link-local/metadata space, or multicast/reserved space - so a plain
// service name like "app" that DNS maps to the container's own address cannot slip
// through. See the OWASP SSRF Prevention Cheat Sheet linked from this challenge.
async function isSelfOrInternalTarget (rawUrl: string): Promise<boolean> {
  let target: URL
  try {
    target = new URL(rawUrl)
  } catch {
    return true // not a well-formed absolute URL - nothing legitimate to fetch here
  }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return true // e.g. file:, data:, gopher: - never a legitimate avatar source
  }

  // URL.hostname keeps the square brackets around an IPv6 literal; strip them so the
  // address classifier and the resolver both see a bare host.
  const host = target.hostname.toLowerCase()
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host

  // Obvious internal names, refused before we spend a DNS lookup on them.
  if (bare === 'localhost' || bare.endsWith('.localhost')) return true
  if (bare === 'metadata' || bare === 'metadata.google.internal') return true

  // Already an IP literal (dotted IPv4, or an IPv6 literal that arrived in brackets)?
  // Classify it directly - no name to resolve.
  if (host.startsWith('[') || /^(\d{1,3}\.){3}\d{1,3}$/.test(bare)) {
    return isDisallowedAddress(bare)
  }

  // A single-label hostname (no dot at all) is never a legitimate public avatar
  // source: it is either an internal service alias handed out by the container /
  // orchestrator DNS - e.g. the very "app" name this deployment answers to on
  // app:3000 - or a bare integer/octal/hex encoding of a loopback address such as
  // http://2130706433/ (== 127.0.0.1). Refuse the whole class without a lookup.
  if (!bare.includes('.')) return true

  // The part every earlier attempt missed: an ordinary-looking domain name can still
  // point at an internal address. Checking only the literal string lets "app" (and
  // any DNS-rebinding host) sail through, because fetch() then resolves it via DNS to
  // the container's own private address and completes the self-attack. So resolve the
  // name the same way fetch() will - through the OS resolver - and refuse if ANY of
  // the returned addresses is internal. A resolution failure is treated as "do not
  // fetch" rather than waved through.
  try {
    const records = await dns.promises.lookup(bare, { all: true })
    return records.some((record) => isDisallowedAddress(record.address))
  } catch {
    return true
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (await isSelfOrInternalTarget(url)) {
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
