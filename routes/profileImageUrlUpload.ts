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

function isInternalAddress (address: string): boolean {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19))
  }
  const ip = address.toLowerCase().split('%')[0]
  if (ip.startsWith('::ffff:')) {
    const mapped = ip.substring(7)
    if (net.isIPv4(mapped)) return isInternalAddress(mapped)
    const [high, low] = mapped.split(':').map((group) => parseInt(group, 16))
    return isInternalAddress([high >> 8, high & 255, low >> 8, low & 255].join('.'))
  }
  return ip === '::' || ip === '::1' || /^f[cd]/.test(ip) || /^fe[89ab]/.test(ip)
}

async function isPubliclyFetchable (imageUrl: unknown): Promise<boolean> {
  let url: URL
  try {
    url = new URL(imageUrl as string)
  } catch {
    return false
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(hostname)) return !isInternalAddress(hostname)
  try {
    const addresses = await dns.lookup(hostname, { all: true })
    return addresses.length > 0 && addresses.every(({ address }) => !isInternalAddress(address))
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const fetchable = await isPubliclyFetchable(url)
      if (fetchable && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!fetchable) {
            throw new Error('imageUrl must be an http(s) URL resolving to a public address')
          }
          const response = await fetch(url, { redirect: 'manual' })
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
