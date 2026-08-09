/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

/**
 * Checks whether a user-supplied image URL must be blocked from being fetched by the
 * server on the user's behalf, to prevent Server-Side Request Forgery (SSRF) attacks
 * (CWE-918) against internal/local infrastructure (loopback, link-local and private IP
 * ranges) or via non-http(s) schemes (e.g. file://). URLs that are simply malformed or
 * whose hostname cannot be resolved are *not* considered forbidden here - they are left
 * to fail naturally when actually fetched, same as before this check was introduced.
 */
async function isForbiddenImageUrl (url: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return true
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|]$/g, '')
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return true
  }

  // If the hostname is itself a literal IP address, check it directly.
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) || hostname.includes(':')) {
    return utils.isPrivateOrReservedIpAddress(utils.toSimpleIpAddress(hostname))
  }

  // Otherwise resolve the hostname and make sure none of the resolved addresses
  // point at internal/private infrastructure (also mitigates naive DNS rebinding).
  try {
    const records = await dns.lookup(hostname, { all: true })
    return records.some(({ address }) => utils.isPrivateOrReservedIpAddress(utils.toSimpleIpAddress(address)))
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
        if (typeof url !== 'string' || (await isForbiddenImageUrl(url))) {
          next(new Error('Invalid or forbidden image URL. Only public http(s) URLs are allowed.'))
          return
        }
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
