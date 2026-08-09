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

// Hostnames that resolve to the host itself or to infrastructure only reachable from
// inside the deployment. Fetching these on a caller's behalf is server-side request
// forgery, not an avatar download.
const BLOCKED_HOST_PATTERNS = [
  'localhost',
  '127.',
  '0.0.0.0',
  '10.',
  '192.168.',
  '169.254.',
  '[',
  'metadata'
]

function isSafeOutboundUrl (candidate: string) {
  let parsed
  try {
    parsed = new URL(candidate)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }
  const host = parsed.hostname.toLowerCase()
  if (BLOCKED_HOST_PATTERNS.some(prefix => host === prefix || host.startsWith(prefix))) {
    return false
  }
  // 172.16.0.0/12
  const privateB = host.match(new RegExp('^172[.]([0-9]+)[.]'))
  if (privateB !== null) {
    const second = Number(privateB[1])
    if (second >= 16 && second <= 31) {
      return false
    }
  }
  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!isSafeOutboundUrl(url)) {
            throw new Error('image url is not an allowed outbound target')
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          // Only an outbound request that actually reached the internal endpoint counts as
          // abuse. The marker used to be set from the URL string alone, before the
          // outbound guard above ran, so a request this handler refused to make was still
          // recorded as a successful forgery.
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
