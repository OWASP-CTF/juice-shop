/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import fs from 'node:fs/promises'
import net from 'node:net'
import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response) => {
    if (req.body.imageUrl !== undefined) {
      const loggedInUser = security.authenticatedUsers.from(req)
      if (!loggedInUser) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }

      let imageUrl: URL
      try {
        imageUrl = await validateExternalUrl(req.body.imageUrl)
      } catch {
        res.status(400).json({ error: 'Only public HTTP(S) image URLs are allowed.' })
        return
      }

      try {
        const response = await fetch(imageUrl, { redirect: 'error' })
        if (!response.ok) throw new Error('Image URL returned a non-OK status code')

        const extensionByType: Record<string, string> = {
          'image/gif': 'gif',
          'image/jpeg': 'jpg',
          'image/png': 'png'
        }
        const contentType = response.headers.get('content-type')?.split(';')[0].toLowerCase() ?? ''
        const ext = extensionByType[contentType]
        if (!ext) throw new Error('Unsupported image type')

        const buffer = await readResponseBody(response)

        const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
        await fs.writeFile(filePath, buffer)
        const user = await UserModel.findByPk(loggedInUser.data.id)
        await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
      } catch (error) {
        logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}`)
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

async function readResponseBody (response: globalThis.Response): Promise<Buffer> {
  if (!response.body) throw new Error('Image response has no body')
  const reader = response.body.getReader()
  const chunks: Buffer[] = []
  let size = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    if (!value) throw new Error('Image response returned no data')
    size += value.byteLength
    if (size > 200000) {
      await reader.cancel()
      throw new Error('Image is too large')
    }
    chunks.push(Buffer.from(value))
  }
  return Buffer.concat(chunks)
}

async function validateExternalUrl (value: unknown): Promise<URL> {
  if (typeof value !== 'string') throw new Error('Invalid URL')
  const url = new URL(value)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Invalid URL')
  }

  const hostname = url.hostname.toLowerCase()
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('Private host')
  }

  const addresses = await dns.lookup(hostname, { all: true })
  if (addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error('Private host')
  }
  return url
}

function isPrivateAddress (address: string): boolean {
  if (net.isIP(address) === 4) {
    const octets = address.split('.').map(Number)
    const [first, second] = octets
    return first === 0 || first === 10 || first === 127 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 0 && octets[2] === 0) ||
      (first === 192 && second === 168) ||
      (first === 198 && (second === 18 || second === 19)) ||
      first >= 224
  }

  const normalized = address.toLowerCase()
  return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') ||
    normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb') ||
    normalized.startsWith('::ffff:') && isPrivateAddress(normalized.substring(7))
}
