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
  return { internal: false }
}

/* Whether a url is one this handler would have been willing to fetch. Used to decide what may
   be stored, so a target the guard turned away is not written to the profile instead. */
const isFetchableUrl = async (rawUrl: string) => {
  try {
    await assertUrlIsSafeToFetch(rawUrl)
    return true
  } catch {
    return false
  }
}

const fetchImage = async (rawUrl: string) => {
  let currentUrl = rawUrl
  let reachedInternalTarget = false
  for (let hop = 0; hop <= 3; hop++) {
    const { internal } = await assertUrlIsSafeToFetch(currentUrl)
    reachedInternalTarget = reachedInternalTarget || internal
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('url responded with a redirect without a target')
      }
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return { response, reachedInternalTarget }
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
          const { response, reachedInternalTarget } = await fetchImage(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          /* A forgery is the server being made to reach something the caller could not. Keying
             off the url string alone meant an ordinary public host whose path merely spelled the
             same words recorded a successful forgery - a request the caller could have made
             themselves. This now requires a hop to have actually landed on an internal target,
             which the guard above refuses to allow. */
          if (reachedInternalTarget && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            /* Falling back to the raw url turned "we refused to fetch this" into "we stored
               this": profileImage is handed back out by whoami and rendered as an img src, so a
               target the guard turned away came straight back out of the shop. */
            if (!await isFetchableUrl(url)) {
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; image link refused, keeping the current profile image`)
              res.location(process.env.BASE_PATH + '/profile')
              res.redirect(process.env.BASE_PATH + '/profile')
              return
            }
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
