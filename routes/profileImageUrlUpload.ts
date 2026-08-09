/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const ALLOWED_PROTOCOLS = ['http:', 'https:']
const BLOCKED_HOSTNAMES = ['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback', 'metadata', 'metadata.google.internal']
const MAX_IMAGE_SIZE_IN_BYTES = 5 * 1024 * 1024
const REQUEST_TIMEOUT_IN_MS = 10000
const MAX_REDIRECTS = 3

/* Signals that a URL must not be requested by the server at all. Such URLs are neither fetched nor
   remembered as profile image, so they can be used neither to probe the internal network nor to store
   arbitrary strings in the user profile. */
class BlockedUrlError extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'BlockedUrlError'
  }
}

function isBlockedIPv4Address (address: string) {
  const octets = address.split('.').map(Number)
  const [first, second] = octets
  if (first === 0) return true // "this" network 0.0.0.0/8
  if (first === 10) return true // private 10.0.0.0/8
  if (first === 127) return true // loopback 127.0.0.0/8
  if (first === 100 && second >= 64 && second <= 127) return true // carrier-grade NAT 100.64.0.0/10
  if (first === 169 && second === 254) return true // link-local 169.254.0.0/16 incl. cloud metadata
  if (first === 172 && second >= 16 && second <= 31) return true // private 172.16.0.0/12
  if (first === 192 && second === 0) return true // IETF protocol assignments 192.0.0.0/24 and TEST-NET-1
  if (first === 192 && second === 168) return true // private 192.168.0.0/16
  if (first === 198 && (second === 18 || second === 19)) return true // benchmarking 198.18.0.0/15
  if (first >= 224) return true // multicast, reserved and broadcast 224.0.0.0/3
  return false
}

function isBlockedIPv6Address (address: string) {
  const normalizedAddress = address.toLowerCase().split('%')[0] // drop any zone index
  const embeddedIPv4 = /^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/.exec(normalizedAddress)
  if (embeddedIPv4 !== null) return isBlockedIPv4Address(embeddedIPv4[1]) // IPv4-mapped/compatible address
  const firstGroup = normalizedAddress.startsWith('::') ? 0 : parseInt(normalizedAddress.split(':')[0], 16)
  if (Number.isNaN(firstGroup)) return true
  if (firstGroup === 0) return true // unspecified ::, loopback ::1 and other embedded addresses
  if ((firstGroup & 0xfe00) === 0xfc00) return true // unique local fc00::/7
  if ((firstGroup & 0xffc0) === 0xfe80) return true // link-local fe80::/10
  if ((firstGroup & 0xffc0) === 0xfec0) return true // site-local fec0::/10
  if ((firstGroup & 0xff00) === 0xff00) return true // multicast ff00::/8
  return false
}

function isBlockedAddress (address: string) {
  const family = net.isIP(address)
  if (family === 4) return isBlockedIPv4Address(address)
  if (family === 6) return isBlockedIPv6Address(address)
  return true // fail closed on anything that is not a parseable IP address
}

/* Parses the given URL and makes sure that requesting it cannot reach anything but a public host over
   HTTP(S). Throws a BlockedUrlError for everything that violates the policy. */
async function assertSafeRequestTarget (candidateUrl: string): Promise<URL> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(candidateUrl)
  } catch {
    throw new BlockedUrlError('URL cannot be parsed')
  }
  if (!ALLOWED_PROTOCOLS.includes(parsedUrl.protocol)) {
    throw new BlockedUrlError(`protocol "${parsedUrl.protocol}" is not supported`)
  }
  if (parsedUrl.username !== '' || parsedUrl.password !== '') {
    throw new BlockedUrlError('URL must not contain credentials')
  }
  const hostname = parsedUrl.hostname.replace(/^\[/, '').replace(/\]$/, '').toLowerCase() // unwrap IPv6 literals
  if (hostname === '') {
    throw new BlockedUrlError('URL has no hostname')
  }
  if (BLOCKED_HOSTNAMES.includes(hostname) || hostname.endsWith('.localhost')) {
    throw new BlockedUrlError(`hostname "${hostname}" is not allowed`)
  }
  let addresses: string[]
  if (net.isIP(hostname) !== 0) {
    addresses = [hostname]
  } else {
    try {
      addresses = (await dns.lookup(hostname, { all: true })).map((entry) => entry.address)
    } catch (error) {
      /* An unresolvable hostname cannot be turned into a request against an internal service, so this is
         treated like any other retrieval problem instead of a policy violation. */
      throw new Error(`hostname "${hostname}" cannot be resolved: ${utils.getErrorMessage(error)}`)
    }
  }
  if (addresses.length === 0) {
    throw new BlockedUrlError(`hostname "${hostname}" does not resolve to any address`)
  }
  for (const address of addresses) {
    if (isBlockedAddress(address)) {
      throw new BlockedUrlError(`hostname "${hostname}" resolves to non-public address ${address}`)
    }
  }
  return parsedUrl
}

function createSizeLimitingStream (maxBytes: number) {
  let receivedBytes = 0
  return new Transform({
    transform (chunk: Buffer, _encoding, callback) {
      receivedBytes += chunk.length
      if (receivedBytes > maxBytes) {
        callback(new Error(`image exceeds the maximum allowed size of ${maxBytes} bytes`))
        return
      }
      callback(null, chunk)
    }
  })
}

/* Retrieves the image while following redirects manually, so that every single hop has to pass the same
   policy as the URL originally submitted by the user. */
async function retrieveImage (url: URL, req: Request) {
  let currentUrl = url
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (currentUrl.href.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
    const response = await fetch(currentUrl.href, { redirect: 'manual', signal: AbortSignal.timeout(REQUEST_TIMEOUT_IN_MS) })
    if (response.status >= 300 && response.status <= 308 && response.headers.has('location')) {
      await response.body?.cancel()
      currentUrl = await assertSafeRequestTarget(new URL(response.headers.get('location') as string, currentUrl).href)
      continue
    }
    if (!response.ok || !response.body) {
      throw new Error('url returned a non-OK status code or an empty body')
    }
    if (Number(response.headers.get('content-length')) > MAX_IMAGE_SIZE_IN_BYTES) {
      await response.body.cancel()
      throw new Error(`image exceeds the maximum allowed size of ${MAX_IMAGE_SIZE_IN_BYTES} bytes`)
    }
    return response
  }
  throw new Error(`url exceeded the maximum of ${MAX_REDIRECTS} redirects`)
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        let safeUrl: URL
        try {
          safeUrl = await assertSafeRequestTarget(url)
        } catch (error) {
          /* Fail closed: a URL the server must not request is not stored as profile image either. */
          logger.warn(`Rejected profile image URL: ${utils.getErrorMessage(error)}`)
          res.location(process.env.BASE_PATH + '/profile')
          res.redirect(process.env.BASE_PATH + '/profile')
          return
        }
        try {
          const response = await retrieveImage(safeUrl, req)
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await pipeline(Readable.fromWeb(response.body as any), createSizeLimitingStream(MAX_IMAGE_SIZE_IN_BYTES), fileStream)
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          if (error instanceof BlockedUrlError) {
            logger.warn(`Rejected profile image URL: ${utils.getErrorMessage(error)}`)
          } else {
            try {
              const user = await UserModel.findByPk(loggedInUser.data.id)
              /* Only the normalized URL is stored, never the raw user input, so that it cannot break out of
                 the contexts the profile image is later used in. */
              await user?.update({ profileImage: safeUrl.href })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
            } catch (error) {
              next(error)
              return
            }
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
