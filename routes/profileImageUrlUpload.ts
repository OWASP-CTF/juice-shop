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

const maxImageSize = 200000

function isPrivateAddress (address: string): boolean {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19))
  }

  const normalized = address.toLowerCase().split('%')[0]
  if (normalized.startsWith('::ffff:')) {
    const mappedAddress = normalized.slice(7)
    if (net.isIPv4(mappedAddress)) {
      return isPrivateAddress(mappedAddress)
    }
    const [high, low] = mappedAddress.split(':').map(group => parseInt(group, 16))
    return isPrivateAddress([high >> 8, high & 255, low >> 8, low & 255].join('.'))
  }
  return normalized === '::' || normalized === '::1' || /^f[cd]/.test(normalized) || /^fe[89ab]/.test(normalized)
}

async function validateImageUrl (value: unknown): Promise<{ url: URL, extension: string }> {
  let imageUrl: URL
  try {
    imageUrl = new URL(String(value))
  } catch {
    throw new Error('Invalid image URL')
  }
  if (!['http:', 'https:'].includes(imageUrl.protocol)) {
    throw new Error('Invalid image URL protocol')
  }

  const extension = imageUrl.pathname.split('.').pop()?.toLowerCase() ?? ''
  if (!['jpg', 'jpeg', 'png', 'gif'].includes(extension)) {
    throw new Error('Invalid image URL extension')
  }

  const hostname = imageUrl.hostname.replace(/^\[|\]$/g, '')
  const addresses = net.isIP(hostname) ? [{ address: hostname }] : await dns.lookup(hostname, { all: true })
  if (addresses.length === 0 || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error('Image URL must resolve to a public address')
  }
  return { url: imageUrl, extension }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        let validatedUrl: URL
        let extension: string
        try {
          const validated = await validateImageUrl(req.body.imageUrl)
          validatedUrl = validated.url
          extension = validated.extension
        } catch (error) {
          res.status(400).json({ error: utils.getErrorMessage(error) })
          return
        }

        try {
          const response = await fetch(validatedUrl, { redirect: 'error', signal: AbortSignal.timeout(5000) })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const contentLength = Number(response.headers.get('content-length') ?? 0)
          if (contentLength > maxImageSize || !response.headers.get('content-type')?.toLowerCase().startsWith('image/')) {
            throw new Error('url did not return an acceptable image')
          }
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${extension}`, { flags: 'w' })
          const bodyStream = Readable.fromWeb(response.body as any)
          let received = 0
          bodyStream.on('data', (chunk: Buffer) => {
            received += chunk.length
            if (received > maxImageSize) {
              bodyStream.destroy(new Error('image exceeds maximum size'))
            }
          })
          await finished(bodyStream.pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${extension}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: validatedUrl.toString() })
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
