/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const allowedImageHosts = (process.env.PROFILE_IMAGE_URL_ALLOWED_HOSTS ?? 'gravatar.com,www.gravatar.com,secure.gravatar.com')
  .split(',')
  .map((host) => host.trim().toLowerCase())
  .filter((host) => host.length > 0)

// Only URLs that positively match the allow-list of image hosts may be retrieved or stored.
function parseAllowedImageUrl (imageUrl: string): URL | null {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(imageUrl)
  } catch {
    return null
  }
  if (parsedUrl.protocol !== 'https:') return null
  if (parsedUrl.username !== '' || parsedUrl.password !== '') return null
  if (parsedUrl.port !== '') return null
  if (!allowedImageHosts.includes(parsedUrl.hostname.toLowerCase())) return null
  return parsedUrl
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const imageUrl = parseAllowedImageUrl(url)
        if (imageUrl === null) {
          res.status(400).send('Profile image URL must be an HTTPS link to an image on an allowed host')
          return
        }
        try {
          const response = await fetch(imageUrl.href, { redirect: 'error', signal: AbortSignal.timeout(5000) })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          if (!(response.headers.get('content-type') ?? '').startsWith('image/')) {
            throw new Error('url did not return an image')
          }
          const extension = imageUrl.pathname.split('.').slice(-1)[0].toLowerCase()
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(extension) ? extension : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: imageUrl.href })
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
