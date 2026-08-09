/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Transform } from 'node:stream'
import { finished } from 'node:stream/promises'

// Stops the download at the cap instead of letting a remote endpoint decide how much of the
// disk to use.
const boundedBody = (limit: number) => {
  let received = 0
  return new Transform({
    transform (chunk: Buffer, _encoding, callback) {
      received += chunk.length
      if (received > limit) {
        callback(new Error('image exceeds the maximum accepted size'))
        return
      }
      callback(null, chunk)
    }
  })
}
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

const OUTBOUND_TIMEOUT_MS = 10000
// A remote file is written straight to disk, so the download is bounded rather than trusted
// to end. Without a cap an endpoint that never stops sending fills the volume.
const MAX_IMAGE_BYTES = 5 * 1024 * 1024

// The patterns above only see the string that was typed. Names resolve, and `localtest.me`,
// `2130706433`, `0x7f000001` and `0177.0.0.1` all end up at 127.0.0.1 without matching any
// of them, so the address the request would really be sent to has to be checked as well.
// This is an allowlist: only publicly routable unicast addresses are accepted, everything
// else (loopback, private, link-local/metadata, CGNAT, multicast, reserved) is refused.
const MAX_REDIRECT_HOPS = 3
const MAX_STORED_IMAGE_LINK_LENGTH = 2048

function isPublicUnicastIPv4 (address: string) {
  const octets = address.split('.').map(Number)
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false
  }
  const [a, b, c] = octets
  if (a === 0 || a === 10 || a === 127) return false // this network, private, loopback
  if (a === 100 && b >= 64 && b <= 127) return false // 100.64.0.0/10 carrier grade NAT
  if (a === 169 && b === 254) return false // 169.254.0.0/16 link-local incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return false // 172.16.0.0/12 private
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false // IETF protocol assignments, TEST-NET-1
  if (a === 192 && b === 88 && c === 99) return false // 6to4 relay anycast
  if (a === 192 && b === 168) return false // 192.168.0.0/16 private
  if (a === 198 && (b === 18 || b === 19)) return false // 198.18.0.0/15 benchmarking
  if (a === 198 && b === 51 && c === 100) return false // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false // TEST-NET-3
  if (a >= 224) return false // multicast, reserved and the broadcast address
  return true
}

function isPublicUnicastIPv6 (address: string) {
  const plain = address.split('%')[0].toLowerCase()
  if (plain === '::' || plain === '::1') return false // unspecified, loopback
  // IPv4-mapped, IPv4-compatible and NAT64 forms carry an IPv4 address in their tail.
  const embedded = plain.match(/(\d{1,3}(?:[.]\d{1,3}){3})$/)
  if (embedded !== null) {
    return isPublicUnicastIPv4(embedded[1])
  }
  const groups = plain.split(':')
  const leading = groups[0] === '' ? 0 : Number.parseInt(groups[0], 16)
  if (!Number.isFinite(leading)) return false // unparseable, so refuse it
  if (leading === 0) return false // ::/16 covers the mapped/compatible forms in hex notation
  if ((leading & 0xfe00) === 0xfc00) return false // fc00::/7 unique local
  if ((leading & 0xffc0) === 0xfe80) return false // fe80::/10 link-local
  if ((leading & 0xff00) === 0xff00) return false // ff00::/8 multicast
  if (leading === 0x2002) return false // 6to4, embeds an arbitrary IPv4 address
  if (leading === 0x2001) {
    const secondGroup = groups.length > 1 ? groups[1] : ''
    const second = secondGroup === '' ? 0 : Number.parseInt(secondGroup, 16)
    if (second === 0 || second === 0xdb8) return false // Teredo, documentation
  }
  return true
}

function isPublicUnicastAddress (address: string) {
  const version = net.isIP(address)
  if (version === 4) return isPublicUnicastIPv4(address)
  if (version === 6) return isPublicUnicastIPv6(address)
  return false
}

function hostnameOf (parsed: URL) {
  return parsed.hostname.replace(/^\[/, '').replace(/\]$/, '')
}

async function resolveOutboundTarget (candidate: string) {
  const parsed = new URL(candidate)
  const hostname = hostnameOf(parsed)
  const addresses = net.isIP(hostname) !== 0
    ? [hostname]
    : (await dns.lookup(hostname, { all: true })).map((entry) => entry.address)
  if (addresses.length === 0) {
    throw new Error('image url host does not resolve')
  }
  // Every address the name resolves to has to be acceptable, otherwise a host with both a
  // public and an internal record would slip through.
  return { href: parsed.href, internal: !addresses.every(isPublicUnicastAddress), address: addresses[0] }
}


// The address is resolved and checked, and then the connection is pinned to that exact
// address. Handing the hostname to the HTTP client instead would have it resolve a second
// time, and a name whose record changes between the two lookups - DNS rebinding - answers
// the check with a public address and the connection with an internal one. Pinning removes
// the window: what was validated is what is dialled. The hostname still travels in the URL,
// so TLS verification and virtual hosting are unaffected.
async function requestWithPinnedAddress (target: URL, address: string) {
  const client = target.protocol === 'https:' ? https : http
  return await new Promise<http.IncomingMessage>((resolve, reject) => {
    const request = client.request(target, {
      lookup: (_hostname: string, _options: unknown, callback: (err: Error | null, addr: string, family: number) => void) => {
        callback(null, address, net.isIP(address))
      },
      headers: { accept: 'image/*' }
    } as any, resolve)
    request.on('error', reject)
    request.setTimeout(OUTBOUND_TIMEOUT_MS, () => {
      request.destroy(new Error('image url did not answer in time'))
    })
    request.end()
  })
}

// `fetch` follows redirects on its own and only the first url was ever validated, so a
// public redirector answering `302 Location: http://127.0.0.1:3000/...` walked straight
// past the guard. Follow them here instead and validate every hop.
async function fetchWithValidatedRedirects (candidate: string) {
  let currentUrl = candidate
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    if (!isSafeOutboundUrl(currentUrl)) {
      throw new Error('image url is not an allowed outbound target')
    }
    const target = await resolveOutboundTarget(currentUrl)
    if (target.internal) {
      throw new Error('image url resolves to an address that is not publicly routable')
    }
    const response = await requestWithPinnedAddress(new URL(target.href), target.address)
    const status = response.statusCode ?? 0
    if (status < 300 || status > 399) {
      return { response, reachedInternalTarget: target.internal }
    }
    const location = response.headers.location
    response.resume()
    if (location === undefined) {
      throw new Error('redirect without a location header')
    }
    currentUrl = new URL(location, target.href).href
  }
  throw new Error('too many redirects while retrieving the image')
}

// A url the outbound guard refused must never be written to the profile either: the column
// is handed back out by /rest/user/whoami and rendered as an img src on the profile page,
// so the fallback used to turn "we refused to fetch this" into "we stored this". A url that
// passes the guard but could not be downloaded is still usable as a direct link, which is
// what this fallback is for. Single quotes are escaped so the stored value cannot smuggle
// policy directives into anything that reads it back.
function storableImageLink (candidate: string) {
  if (!isSafeOutboundUrl(candidate)) {
    return null
  }
  const parsed = new URL(candidate)
  const hostname = hostnameOf(parsed)
  if (net.isIP(hostname) !== 0 && !isPublicUnicastAddress(hostname)) {
    return null
  }
  if (parsed.href.length > MAX_STORED_IMAGE_LINK_LENGTH) {
    return null
  }
  return parsed.href.replace(/'/g, '%27')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        // Refuse the disallowed target out loud. Throwing here dropped into the shared catch
        // below, which kept the previous picture and then answered with the same redirect to
        // /profile that a successful upload returns - so a request the server refused to make
        // was indistinguishable from one it made and stored. A caller aiming at an internal
        // address now gets an explicit rejection instead of a silent no-op dressed as success.
        if (!isSafeOutboundUrl(url)) {
          res.status(400).json({ error: 'The image URL is not an allowed outbound target' })
          return
        }
        try {
          const { response, reachedInternalTarget } = await fetchWithValidatedRedirects(url)
          const status = response.statusCode ?? 0
          if (status < 200 || status >= 300) {
            response.resume()
            throw new Error('url returned a non-OK status code')
          }
          // Only an outbound request that actually reached an internal endpoint of this
          // deployment counts as abuse. The marker used to be set from the URL string
          // alone, before the outbound guard above ran, so a request this handler refused
          // to make was still recorded as a successful forgery. The internal-target
          // condition is the second half of that: a public host that merely spells the
          // same path in its URL is a request the caller could have made themselves, not
          // something the server was tricked into.
          if (reachedInternalTarget && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(response.pipe(boundedBody(MAX_IMAGE_BYTES)).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          const directLink = storableImageLink(url)
          if (directLink === null) {
            // Fail closed: input the outbound guard rejected is not persisted either.
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; image link rejected, keeping the current profile image`)
          } else {
            try {
              const user = await UserModel.findByPk(loggedInUser.data.id)
              await user?.update({ profileImage: directLink })
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
