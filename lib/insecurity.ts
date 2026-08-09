/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import { expressjwt as expressJwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

/* The key that signs session tokens used to be a literal in this file, and the matching public
   half was a tracked file served over HTTP. A signing key committed to a repository is a signing
   key handed to every reader of that repository: anybody who had seen the source could mint a
   token for any account, with any role, that this server would then verify as genuine - and no
   later edit could take that back, because the key stays readable in the history. So the pair is
   no longer material that ships with the code at all. It is generated when the process starts,
   which means it exists only in this process's memory, differs between deployments and between
   restarts, and has never been written anywhere it could be read from. Only the public half is
   exported; nothing outside this module has any business holding the private one. */
const sessionSigningKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
})
export const publicKey = sessionSigningKeys.publicKey
const privateKey = sessionSigningKeys.privateKey

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

// Session tokens (JWTs) must be pinned to the single algorithm they were actually
// issued with. Deciding which algorithm to use for verification based on the
// `alg` field inside the (attacker-controlled) token itself allows forged
// tokens - e.g. signed with `alg: none` or resigned with the RSA public key
// used as an HMAC secret - to be accepted as valid sessions.
const SESSION_TOKEN_ALGORITHM = 'RS256'

const hasExpectedJwtAlgorithm = (token?: string): boolean => {
  if (!token) {
    return false
  }
  try {
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString('utf8'))
    return header?.alg === SESSION_TOKEN_ALGORITHM
  } catch {
    return false
  }
}

export const isAuthorized = () => {
  const jwtMiddleware = expressJwt({ secret: publicKey, algorithms: [SESSION_TOKEN_ALGORITHM] })
  return (req: Request, res: Response, next: NextFunction) => {
    if (!hasExpectedJwtAlgorithm(utils.jwtFrom(req))) {
      res.status(401).send()
      return
    }
    jwtMiddleware(req, res, next)
  }
}
/* Nothing may pass, so the gate is handed a key nobody holds: a fresh 256-bit random value that
   is discarded the moment the middleware is built. Math.random is not a source of unguessable
   material - it is seeded from process state and its output stream can be reconstructed from a
   handful of prior draws - and the same middleware factory is called repeatedly, so drawing the
   "impossible" secret from it was the weakest part of a gate whose entire job is to be shut. */
export const denyAll = () => expressJwt({ secret: crypto.randomBytes(32).toString('hex'), algorithms: [SESSION_TOKEN_ALGORITHM] })
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: SESSION_TOKEN_ALGORITHM })
/* The pinned jws@0.2.6 exposes `verify(signature, secretOrKey)`, while the bundled @types/jws
   describes the later three-argument `verify(signature, algorithm, secretOrKey)` form. Calling the
   newer shape against this library passes the algorithm name where the key is expected, so every
   token is checked against the literal string instead of the public half and verification throws
   for genuine sessions as well as forged ones. The call below therefore matches the signature the
   installed library actually implements. Pinning the algorithm is still handled - and must keep
   being handled - by hasExpectedJwtAlgorithm above, which rejects anything whose header is not
   RS256 before it ever reaches this point, because jws reads the algorithm from the token. */
const jwsVerify = jws.verify as unknown as (signature: string, secretOrKey: string) => boolean
export const verify = (token: string) => token && hasExpectedJwtAlgorithm(token) ? jwsVerify(token, publicKey) : false
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

/* A campaign coupon used to be nothing but its own text run through z85. z85 is a transport
   encoding, not a signature: it is public, unkeyed and reversible, so working out what a 90%
   coupon looks like took one call to the same encoder in the other direction. What tells a
   coupon the shop issued apart from one the customer typed has to be something only the shop
   can produce, so each code now carries a keyed tag over its own contents and a code whose tag
   does not recompute is not a coupon at all. The key is minted per process and never leaves it:
   coupons are only valid for the current month, so there is nothing here worth persisting - and
   a key that is never written down cannot be read back out of the source or a backup. */
const couponSigningKey = crypto.randomBytes(32)
const COUPON_TAG_LENGTH = 16

const couponTag = (coupon: string) => {
  return crypto.createHmac('sha256', couponSigningKey).update(coupon).digest('hex').slice(0, COUPON_TAG_LENGTH)
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon) + couponTag(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon || coupon.length <= COUPON_TAG_LENGTH) {
    return undefined
  }
  const decoded = z85.decode(coupon.slice(0, -COUPON_TAG_LENGTH))?.toString()
  if (!decoded || hasValidFormat(decoded) == null) {
    return undefined
  }
  if (coupon.slice(-COUPON_TAG_LENGTH) !== couponTag(decoded)) {
    return undefined
  }
  const parts = decoded.split('-')
  const validity = parts[0]
  if (utils.toMMMYY(new Date()) === validity) {
    const discount = parts[1]
    return parseInt(discount)
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    /* The allow list names the pages the shop is willing to send a visitor to, so those exact
       pages are what it permits. Accepting anything that merely *begins* with an entry still
       lets a destination be extended into somewhere else entirely - a longer host that shares
       the prefix, or extra path and query the shop never vetted - and the outgoing link then
       carries the shop's referrer to a site nobody approved. */
    allowed = allowed || url === allowedUrl
  }
  return allowed
}
// vuln-code-snippet end redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

/* A session token reaches the server by two different routes. XHR calls made by the Angular
   client attach it as a bearer token, but the requests the browser issues on its own behalf --
   documents, stylesheets, images -- carry no Authorization header and identify the session only
   through the `token` cookie. An authorisation check that has to cover both kinds of request
   therefore has to look in both places. The Cookie header is read directly rather than through
   req.cookies so that the decision does not depend on cookie-parsing middleware having been
   mounted earlier in the chain than the check itself. */
export const sessionTokenOf = (req: Request) => {
  const bearerToken = utils.jwtFrom(req)
  if (bearerToken) {
    return bearerToken
  }
  const cookieHeader: string = req.headers?.cookie ?? ''
  const tokenCookie = /(?:^|;)\s*token=([^;]*)/.exec(cookieHeader)
  if (!tokenCookie) {
    return undefined
  }
  const rawValue = tokenCookie[1].trim()
  try {
    return decodeURIComponent(rawValue)
  } catch {
    /* A value that is not valid percent-encoding is judged exactly as it arrived. */
    return rawValue
  }
}

/* Route guard for endpoints that expose operator-only material. The role is taken from the
   verified token payload, so a caller cannot claim it through a header or query parameter.
   The token is resolved via sessionTokenOf so that both bearer-token XHRs and plain browser
   document requests (which carry only the `token` cookie) are covered by the same check. */
export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = sessionTokenOf(req)
    const decodedToken = token ? verify(token) && decode(token) : false
    if (decodedToken?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

/* The browser attaches the `token` cookie to any request another site can make it issue - a
   form post, an image, a link - so on the endpoints that still accept that ambient cookie as
   proof of identity, holding a session is not the same as having asked for the action. Where
   the request came from is what distinguishes the two, and the browser reports that in Origin
   (and, failing that, Referer) as a value page script cannot forge. A request that names no
   source at all proves nothing about who made it either, so it is refused on the same footing
   as one that names somebody else. */
export const sameOriginOnly = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const declaredSource = req.headers.origin ?? req.headers.referer
    let sourceHost: string | undefined
    if (declaredSource !== undefined) {
      try {
        sourceHost = new URL(declaredSource).host
      } catch {
        sourceHost = undefined
      }
    }
    if (sourceHost === undefined || sourceHost !== req.headers.host) {
      res.status(403).json({ error: 'Cross-origin request blocked' })
      return
    }
    next()
  }
}

/* Which basket a request operates on is taken from the URL, so a valid session only proves who
   is asking - never that the row they named is theirs. Every signed-in customer could read (and
   fill) anybody else's basket just by counting up through the ids. The owner recorded on the
   row is compared against the account behind the token before the request is allowed to go on. */
export const isBasketOwner = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { BasketModel } = await import('../models/basket')
      const user = authenticatedUsers.from(req)
      const basket = await BasketModel.findByPk(req.params.id)
      if (!user || (basket != null && basket.UserId !== user.data.id)) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      next()
    } catch (error: unknown) {
      next(error)
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && hasExpectedJwtAlgorithm(token)) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
