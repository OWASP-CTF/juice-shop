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

/* Setting a profile image by URL makes the server, not the browser, issue the request. The
   customer therefore chooses which host the shop connects to, from inside the shop's own network:
   loopback reaches the shop's private endpoints, RFC1918 reaches its neighbours, and 169.254.169.254
   reaches the cloud instance metadata service and the credentials it hands out. Only publicly
   routable http(s) destinations are fetched, and a destination that fails the check is refused
   outright rather than being remembered on the profile. */

const isPublicAddress = (address: string): boolean => {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false
    if (a === 169 && b === 254) return false
    if (a === 172 && b >= 16 && b <= 31) return false
    if (a === 192 && (b === 168 || b === 0)) return false
    if (a === 100 && b >= 64 && b <= 127) return false
    if (a === 198 && (b === 18 || b === 19)) return false
    return true
  }
  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase()
    if (normalized.startsWith('::ffff:')) {
      return isPublicAddress(normalized.substring('::ffff:'.length))
    }
    if (normalized === '::1' || normalized === '::') return false
    if (/^f[cd]/.test(normalized)) return false
    if (/^fe[89ab]/.test(normalized)) return false
    return true
  }
  return false
}

const resolveToPublicHost = async (rawUrl: string) => {
  const url = new URL(rawUrl)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http and https image URLs are supported')
  }
  const hostname = url.hostname.replace(/^\[|]$/g, '')
  if (!hostname) {
    throw new Error('Image URLs must name a host')
  }
  /* Every address the name answers with is checked, not just the first: a name that answers with
     one public and one private address would otherwise be a way through. */
  const addresses = net.isIP(hostname)
    ? [hostname]
    : (await dns.lookup(hostname, { all: true })).map((entry) => entry.address)
  if (addresses.length === 0 || !addresses.every(isPublicAddress)) {
    throw new Error('Image URLs must point to a publicly reachable host')
  }
}

const fetchProfileImage = async (rawUrl: string) => {
  let currentUrl = rawUrl
  /* Redirects are followed by hand so that every hop is checked. Left to the fetch
     implementation, a public host could answer with a redirect to an internal address and the
     check on the first hop would count for nothing. */
  for (let hop = 0; hop <= 3; hop++) {
    await resolveToPublicHost(currentUrl)
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
      if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
      let response
      try {
        response = await fetchProfileImage(url)
        if (!response.ok || !response.body) {
          throw new Error('url returned a non-OK status code or an empty body')
        }
      } catch (error) {
        /* A destination the shop refuses to retrieve is not kept either. Storing the URL on the
           profile and letting the browser load it later would only move the request to the
           customer, and it would leave attacker-chosen content in a rendered attribute. */
        logger.warn(`Rejected profile image URL: ${utils.getErrorMessage(error)}`)
        res.status(400).json({ error: 'The profile image URL could not be retrieved' })
        return
      }
      try {
        const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
        const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
        await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
        const user = await UserModel.findByPk(loggedInUser.data.id)
        await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
      } catch (error) {
        next(error)
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
