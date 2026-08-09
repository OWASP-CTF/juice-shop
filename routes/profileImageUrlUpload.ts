/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { lookup } from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      let parsedUrl: URL
      try {
        parsedUrl = new URL(url)
      } catch {
        res.status(400).send('Invalid image URL')
        return
      }
      if (!['http:', 'https:'].includes(parsedUrl.protocol) || isPrivateHost(parsedUrl.hostname)) {
        res.status(400).send('Invalid image URL')
        return
      }
      try {
        const addresses = await lookup(parsedUrl.hostname, { all: true })
        if (addresses.length === 0 || addresses.some(({ address }) => isPrivateHost(address))) {
          res.status(400).send('Invalid image URL')
          return
        }
      } catch {
        res.status(400).send('Invalid image URL')
        return
      }
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(parsedUrl, { redirect: 'error' })
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

function isPrivateHost (host: string) {
  const normalized = host.replace(/^\[|\]$/g, '').toLowerCase()
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return true
  if (net.isIP(normalized) === 4) {
    const [first, second] = normalized.split('.').map(Number)
    return first === 0 || first === 10 || first === 127 || first === 169 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168)
  }
  if (net.isIP(normalized) === 6) {
    return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:')
  }
  return false
}
