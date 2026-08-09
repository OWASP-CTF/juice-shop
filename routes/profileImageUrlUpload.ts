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

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import logger from '../lib/logger'

// Loopback, private (RFC1918), CGNAT, link-local and unique-local addresses - the
// ranges an SSRF payload would aim at to reach internal services. IPv4-mapped IPv6
// (::ffff:127.0.0.1) is unwrapped first so it cannot slip past as a v6 string.
function isPrivateIp (ip: string): boolean {
  let addr = ip.toLowerCase()
  const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  if (mapped) addr = mapped[1]
  if (net.isIPv4(addr)) {
    const [a, b] = addr.split('.').map(Number)
    return a === 0 || a === 127 || a === 10 ||
      (a === 192 && b === 168) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
  }
  return addr === '::1' || addr === '::' || addr.startsWith('fe80:') || addr.startsWith('fc') || addr.startsWith('fd')
}

// The profile image "from URL" feature must only ever reach a public image host.
// The host is resolved and every resolved address is checked, so numeric/encoded
// forms (http://0x7f000001, http://2130706433) and internal service names alike are
// caught by their real IP - this is server-side request forgery defence
// (A01:2025 SSRF, CWE-918). DNS rebinding between this check and the fetch remains a
// known residual gap.
async function isFetchableImageUrl (raw: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(raw)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost')) {
    return false
  }
  if (net.isIP(host) !== 0) {
    return !isPrivateIp(host)
  }
  try {
    const addresses = await dns.lookup(host, { all: true })
    return addresses.length > 0 && addresses.every((entry) => !isPrivateIp(entry.address))
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (!(await isFetchableImageUrl(url))) {
        logger.warn(`Rejected profile image URL that is not a public http(s) target (possible SSRF): ${url}`)
        res.location(process.env.BASE_PATH + '/profile')
        res.redirect(process.env.BASE_PATH + '/profile')
        return
      }
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          // redirect: 'manual' so a public URL cannot 3xx-bounce the fetch to an
          // internal target after the host check has passed.
          const response = await fetch(url, { redirect: 'manual' })
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
            if (security.isCspSafeUrl(url)) {
              await user?.update({ profileImage: url })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
            } else {
              logger.warn(`Rejected unsafe profile image URL containing CSP-breaking characters: ${url}`)
            }
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
