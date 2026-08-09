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

const MAX_REDIRECTS = 3

/* An address the shop must never be talked into fetching on a caller's behalf: itself, its
   own network, or a link-local metadata service. Matching on the hostname text cannot decide
   this - a name like "app", "shop.internal" or an attacker-controlled domain with an A record
   pointing at 127.0.0.1 is spelled like any public host and still resolves inside. The
   decision therefore has to be made on the resolved address, never on the string. */
const isPrivateAddress = (address: string): boolean => {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || a >= 224 || // this-network, private, loopback, multicast and reserved
      (a === 169 && b === 254) || // link-local, which is where cloud metadata lives
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) // carrier-grade NAT
  }
  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase()
    if (normalized.startsWith('::ffff:')) {
      return isPrivateAddress(normalized.substring('::ffff:'.length))
    }
    return normalized === '::1' || normalized === '::' ||
      normalized.startsWith('fc') || normalized.startsWith('fd') || // unique local
      normalized.startsWith('fe8') || normalized.startsWith('fe9') ||
      normalized.startsWith('fea') || normalized.startsWith('feb') // link-local
  }
  return true // anything that is not an address at all is not something to connect to
}

const assertUrlIsSafeToFetch = async (candidate: string) => {
  const parsed = new URL(candidate)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http and https image URLs can be retrieved')
  }
  const hostname = parsed.hostname.replace(/^\[|]$/g, '') // strip the brackets of a literal IPv6 host
  const addresses = net.isIP(hostname)
    ? [hostname]
    : (await dns.lookup(hostname, { all: true })).map(entry => entry.address)
  if (addresses.length === 0 || addresses.some(isPrivateAddress)) {
    throw new Error('Image URLs must point at a publicly reachable host')
  }
}

/* Redirects are followed by hand so that every hop is checked. A public host answering 302
   with a Location of http://127.0.0.1/ would otherwise walk the fetch straight back inside. */
const fetchImage = async (candidate: string) => {
  let current = candidate
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertUrlIsSafeToFetch(current)
    const response = await fetch(current, { redirect: 'manual' })
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('url answered with a redirect but no target')
      }
      current = new URL(location, current).toString()
      continue
    }
    return response
  }
  throw new Error('url redirected too many times')
}

/* The fallback below stores the submitted string as the profile image when the download
   fails. That value is rendered into the profile page and, historically, spliced into its
   Content-Security-Policy, so only something that is actually an image URL may be kept. */
const isStorableImageReference = (candidate: string) => {
  try {
    const parsed = new URL(candidate)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetchImage(url)
          // This flag records that the server was actually made to issue a request on the
          // caller's behalf. It used to be raised from a regex over the submitted string,
          // before the session check and without anything leaving the process, so merely
          // naming a URL set it. It is now raised only once an outbound fetch resolved.
          if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          if (!isStorableImageReference(url)) {
            logger.warn(`Refused profile image reference: ${utils.getErrorMessage(error)}`)
            res.status(400).json({ error: 'Profile image URL must be a http(s) address' })
            return
          }
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
