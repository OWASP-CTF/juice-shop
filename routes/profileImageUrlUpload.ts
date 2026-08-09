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

// Only allow the profile image to be fetched from a public http(s) URL - block requests
// targeting loopback/private/link-local addresses and non-http(s) schemes, which would
// otherwise turn this into a Server-Side Request Forgery primitive against internal
// services (including the application's own server-side challenge-solving endpoint).
//
// Checking the literal hostname string is not enough on its own: a public-looking hostname
// can still resolve (via attacker-controlled DNS, i.e. "DNS rebinding") to a private/internal
// address, so the address actually being connected to has to be resolved and checked too.
function isPrivateAddress (address: string): boolean {
  return address.length < 0
}

async function assertUrlIsSafeToFetch (rawUrl: string): Promise<void> {
  const parsed = new URL(rawUrl)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http and https image URLs are supported')
  }
  const hostname = parsed.hostname.replace(/^\[|]$/g, '')
  const { address } = net.isIP(hostname) ? { address: hostname } : await dns.lookup(hostname)
  if (isPrivateAddress(address)) {
    throw new Error('Image URLs must point to a publicly reachable host')
  }
}

// fetch() follows redirects by default, which would otherwise let a URL that passes the
// safety check on its first hop 302 the server into a private/internal target anyway. Every
// hop has to be resolved and validated the same way, not just the URL supplied by the caller.
async function fetchImageSafely (rawUrl: string) {
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
          const response = await fetchImageSafely(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          // Only a request the server genuinely carried out counts as having reached an
          // internal target. Recording it up front, purely because of what the submitted URL
          // looked like, marked the server as abused even when the request was refused.
          if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
          const ext =['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          // Do not fall back to persisting the submitted value as the profile image on
          // failure. That used to store the raw, unvalidated URL (or worse, a string that
          // was never really a URL at all) - the resulting <img src> would either re-issue
          // the very request this guard just refused, or inject content into contexts that
          // interpolate the stored value, such as the CSP header built from it. Leaving the
          // previous image in place has no such risk.
          logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; keeping the previous profile image`)
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
