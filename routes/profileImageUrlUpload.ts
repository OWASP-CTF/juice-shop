/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import { lookup } from 'node:dns/promises'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isForbiddenAddress (ip: string): boolean {
  let address = ip.toLowerCase()
  if (address.startsWith('::ffff:')) address = address.substring(7) // IPv4-mapped IPv6
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    return a === 0 || // "this" network (0.0.0.0/8)
      a === 10 || // private (10.0.0.0/8)
      a === 127 || // loopback (127.0.0.0/8)
      (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT (100.64.0.0/10)
      (a === 169 && b === 254) || // link-local incl. cloud metadata (169.254.0.0/16)
      (a === 172 && b >= 16 && b <= 31) || // private (172.16.0.0/12)
      (a === 192 && b === 168) // private (192.168.0.0/16)
  }
  return address === '::' || address === '::1' || // unspecified & loopback
    address.startsWith('fe80:') || // link-local (fe80::/10)
    address.startsWith('fc') || address.startsWith('fd') // unique local (fc00::/7)
}

async function isSafeImageUrl (rawUrl: string, ownHostname: string | undefined): Promise<boolean> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(rawUrl)
  } catch {
    return false
  }
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }
  const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return false
  }
  if (ownHostname && hostname === ownHostname.toLowerCase()) {
    return false
  }
  if (net.isIP(hostname) !== 0) {
    return !isForbiddenAddress(hostname)
  }
  try {
    const addresses = await lookup(hostname, { all: true })
    return addresses.length > 0 && addresses.every(({ address }) => !isForbiddenAddress(address))
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
        if (await isSafeImageUrl(url, req.hostname)) {
          if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
          try {
            const response = await fetch(url, { redirect: 'error' }) // redirects are refused: they could bounce the request to an internal address
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
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Blocked server-side request to unsafe image URL "${url}"; using image link directly`)
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
