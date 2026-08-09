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

const isPrivateAddress = (address: string) => {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
  }
  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase()
    if (normalized.startsWith('::ffff:')) {
      return isPrivateAddress(normalized.substring('::ffff:'.length))
    }
    return normalized === '::1' || normalized === '::' ||
      normalized.startsWith('fc') || normalized.startsWith('fd') ||
      normalized.startsWith('fe8') || normalized.startsWith('fe9') ||
      normalized.startsWith('fea') || normalized.startsWith('feb')
  }
  return true
}

/* Only public http(s) targets may be retrieved, so the shop cannot be abused as a proxy into
   its own network or into cloud metadata services. Every redirect hop is checked as well. */
const assertUrlIsSafeToFetch = async (rawUrl: string) => {
  const url = new URL(rawUrl)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http and https image URLs are supported')
  }
  const hostname = url.hostname.replace(/^\[|]$/g, '')
  const { address } = net.isIP(hostname) ? { address: hostname } : await dns.lookup(hostname)
  if (isPrivateAddress(address)) {
    throw new Error('Image URLs must point to a publicly reachable host')
  }
}

const fetchImage = async (rawUrl: string) => {
  let currentUrl = rawUrl
  for (let hop = 0; hop <= 3; hop++) {
    await assertUrlIsSafeToFetch(currentUrl)
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('url responded with a redirect without a target')
      }
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return response
  }
  throw new Error('url redirected too many times')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetchImage(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          /* A profile image URL only ever names a picture. Refusing to keep whatever a URL
             happens to return stops the shop being used to reach an endpoint for its effect
             rather than for its content. */
          const contentType = response.headers.get('content-type') ?? ''
          if (!contentType.toLowerCase().startsWith('image/')) {
            throw new Error('url did not return an image')
          }
          if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
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
