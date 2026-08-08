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

const FORBIDDEN_IPV4_RANGES = [
  /^0\./, // "this network" (0.0.0.0/8)
  /^10\./, // private (10.0.0.0/8)
  /^127\./, // loopback (127.0.0.0/8)
  /^169\.254\./, // link-local incl. cloud metadata 169.254.169.254 (169.254.0.0/16)
  /^172\.(1[6-9]|2\d|3[01])\./, // private (172.16.0.0/12)
  /^192\.168\./ // private (192.168.0.0/16)
]

function isForbiddenAddress (ip: string): boolean {
  let normalized = ip.replace(/^::ffff:/i, '')
  const mappedHex = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(normalized) // IPv4-mapped address in hex form, e.g. ::ffff:7f00:1
  if (mappedHex !== null) {
    const [hi, lo] = [parseInt(mappedHex[1], 16), parseInt(mappedHex[2], 16)]
    normalized = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`
  }
  if (net.isIPv4(normalized)) {
    return FORBIDDEN_IPV4_RANGES.some((range) => range.test(normalized))
  }
  const lower = normalized.toLowerCase()
  return lower === '::' || lower === '::1' || // unspecified / loopback
    lower.startsWith('fc') || lower.startsWith('fd') || // unique-local (fc00::/7)
    /^fe[89ab]/.test(lower) // link-local (fe80::/10)
}

async function isSafePublicImageUrl (url: unknown): Promise<boolean> {
  if (typeof url !== 'string') return false
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return false
  if (net.isIP(hostname) !== 0) return !isForbiddenAddress(hostname)
  try {
    const addresses = await dns.lookup(hostname, { all: true })
    return addresses.length > 0 && addresses.every(({ address }) => !isForbiddenAddress(address))
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (!(await isSafePublicImageUrl(url))) {
        res.status(403)
        res.send('Error: Blocked illegal image URL! Only public http(s) URLs are allowed.')
        return
      }
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
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
