/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import dns from 'node:dns/promises'
import net from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import logger from '../lib/logger'

const MAX_PROFILE_IMAGE_BYTES = 2 * 1024 * 1024
const imageExtensions = new Map([
  ['image/jpeg', 'jpg'],
  ['image/png', 'png'],
  ['image/gif', 'gif'],
  ['image/webp', 'webp']
])

function isPrivateIpv4 (address: string) {
  const octets = address.split('.').map(Number)
  if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return true
  }
  const [a, b] = octets
  return a === 0 || a === 10 || a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224
}

function isPrivateAddress (address: string) {
  const normalized = address.toLowerCase().split('%')[0]
  if (net.isIPv4(normalized)) {
    return isPrivateIpv4(normalized)
  }
  if (!net.isIPv6(normalized)) {
    return true
  }
  if (normalized === '::' || normalized === '::1' || normalized.startsWith('::ffff:') || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb') || normalized.startsWith('ff')) {
    return true
  }
  return false
}

/* Validate both the URL spelling and every address it currently resolves to.
   Redirects are disabled at fetch time, so a public first hop cannot bounce a
   request into loopback, link-local, or an RFC1918 service. */
export async function fetchableProfileImageUrl (candidate: unknown) {
  if (typeof candidate !== 'string') {
    return undefined
  }
  let parsed: URL
  try {
    parsed = new URL(candidate)
  } catch {
    return undefined
  }
  if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.username !== '' || parsed.password !== '') {
    return undefined
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost') || host === '::1' || host === '0.0.0.0') {
    return undefined
  }
  const addresses = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true, verbatim: true })).map(({ address }) => address)
  if (addresses.length === 0 || addresses.some(isPrivateAddress)) {
    return undefined
  }
  return parsed
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const url = await fetchableProfileImageUrl(req.body.imageUrl)
          if (url === undefined) {
            res.status(400).send('Invalid image URL.')
            return
          }
          const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000) })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const contentType = response.headers.get('content-type')?.split(';', 1)[0].toLowerCase()
          const ext = contentType ? imageExtensions.get(contentType) : undefined
          if (ext === undefined) {
            throw new Error('url did not return a supported image type')
          }
          const declaredLength = Number(response.headers.get('content-length') ?? 0)
          if (declaredLength > MAX_PROFILE_IMAGE_BYTES) {
            throw new Error('profile image is too large')
          }
          const image = Buffer.from(await response.arrayBuffer())
          if (image.length === 0 || image.length > MAX_PROFILE_IMAGE_BYTES) {
            throw new Error('profile image is empty or too large')
          }
          await fs.writeFile(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, image, { flag: 'w' })
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          logger.warn('Rejected remote user profile image')
          res.status(400).send('Unable to retrieve a supported profile image.')
          return
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
