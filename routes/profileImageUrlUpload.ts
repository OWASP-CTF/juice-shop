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

// Blocks the classic SSRF bypasses (loopback, link-local/cloud-metadata,
// RFC1918 private ranges, IPv6 equivalents) so the imageUrl feature cannot
// be abused to make the server issue requests to itself or other internal
// hosts. See OWASP SSRF Prevention Cheat Sheet.
function isForbiddenAddress (address: string): boolean {
  const type = net.isIP(address)
  if (type === 4) {
    const octets = address.split('.').map(Number)
    const [a, b] = octets
    if (a === 127) return true // loopback
    if (a === 10) return true // RFC1918
    if (a === 172 && b >= 16 && b <= 31) return true // RFC1918
    if (a === 192 && b === 168) return true // RFC1918
    if (a === 169 && b === 254) return true // link-local incl. cloud metadata (169.254.169.254)
    if (a === 100 && b >= 64 && b <= 127) return true // carrier-grade NAT
    if (a === 0) return true // "this" network
    if (a >= 224) return true // multicast/reserved
    return false
  }
  if (type === 6) {
    const normalized = address.toLowerCase()
    if (normalized === '::1' || normalized === '::') return true
    if (normalized.startsWith('fe80:') || normalized.startsWith('fc') || normalized.startsWith('fd')) return true // link-local / unique-local
    const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (mapped != null) return isForbiddenAddress(mapped[1])
    return false
  }
  return true // not a valid literal IP -> treat as unsafe
}

async function assertUrlIsSafe (rawUrl: string): Promise<void> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    throw new Error('invalid url')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('unsupported protocol for url')
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  if (hostname.toLowerCase() === 'localhost') {
    throw new Error('requests to localhost are not allowed')
  }
  const literalIpType = net.isIP(hostname)
  if (literalIpType !== 0) {
    if (isForbiddenAddress(hostname)) {
      throw new Error('requests to internal/private addresses are not allowed')
    }
    return
  }
  // Resolve the hostname ourselves and vet every address it can return so
  // DNS rebinding cannot be used to reach internal hosts either.
  const records = await dns.lookup(hostname, { all: true, verbatim: true })
  if (records.length === 0 || records.some(record => isForbiddenAddress(record.address))) {
    throw new Error('requests to internal/private addresses are not allowed')
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
          await assertUrlIsSafe(url)
          const response = await fetch(url, { redirect: 'error' })
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
