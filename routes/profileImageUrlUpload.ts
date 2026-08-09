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

/* An address the shop can reach but the caller cannot: loopback, the private ranges, the
   link-local block that carries cloud metadata, and the carrier-grade NAT range. */
const isInternalAddress = (address: string) => {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
  }
  if (net.isIPv6(address)) {
    const plain = address.toLowerCase()
    if (plain.startsWith('::ffff:')) return isInternalAddress(plain.slice('::ffff:'.length))
    return plain === '::1' || plain === '::' || plain.startsWith('fc') || plain.startsWith('fd') ||
      plain.startsWith('fe8') || plain.startsWith('fe9') || plain.startsWith('fea') || plain.startsWith('feb')
  }
  return true
}

/* Where the url would actually send the request, rather than what it says. Names resolve, and
   localtest.me, 2130706433 and 0x7f000001 all arrive at 127.0.0.1 without looking like it. */
const resolvesInternally = async (rawUrl: string) => {
  let parsed
  try {
    parsed = new URL(rawUrl)
  } catch {
    return true
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return true
  }
  const hostname = parsed.hostname.replace(/^\[|]$/g, '')
  if (net.isIP(hostname)) {
    return isInternalAddress(hostname)
  }
  try {
    const resolved = await dns.lookup(hostname, { all: true })
    return resolved.length === 0 || resolved.some((entry) => isInternalAddress(entry.address))
  } catch {
    return true
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      /* The shop must not be usable as a way into its own network. The target is checked
         before anything is fetched, and a caller aiming at an internal address is told so
         rather than being answered with the redirect a successful upload returns. */
      if (await resolvesInternally(url)) {
        res.status(400).json({ error: 'The image URL must point to a publicly reachable host' })
        return
      }
      /* Only a request the shop was actually made to send counts. This used to be set from the
         url string before the fetch, and before the session was even checked, so submitting the
         text alone recorded a forgery that never happened. */
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
