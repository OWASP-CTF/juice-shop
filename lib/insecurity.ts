/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import { BasketModel } from '../models/basket'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

// A session signing key shipped in the source signs a valid token for every reader of the source,
// so the pair is minted per boot. Nothing outside this module needs the private half.
const sessionKeyPair = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
})
export const publicKey = sessionKeyPair.publicKey
const privateKey = sessionKeyPair.privateKey

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
  invalidate: (token: string) => void
  invalidateAllFor: (userId: number, exceptToken?: string) => void
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

const tokenAlgorithm = 'RS256'

// Sessions live in an in-memory map, so a token stays usable until it is explicitly revoked here.
const invalidatedTokens = new Set<string>()
export const isInvalidated = (token?: string) => !!token && invalidatedTokens.has(utils.unquote(token))

export const isAuthorized = () => expressjwt({ secret: publicKey, algorithms: [tokenAlgorithm] })
// A state change authorised by the ambient token cookie must not be triggerable from another site.
export const sameOriginOnly = () => (req: Request, res: Response, next: NextFunction) => {
  const source = req.headers.origin ?? req.headers.referer
  let sourceHost
  if (source !== undefined) {
    try {
      sourceHost = new URL(source).host
    } catch {
      sourceHost = undefined
    }
  }
  // An absent or unparsable Origin/Referer proves nothing about the caller, so it cannot pass either.
  if (sourceHost === undefined || sourceHost !== req.headers.host) {
    res.status(403).json({ error: 'Cross-origin request blocked' })
    return
  }
  next()
}

// Not a JWT check: these routes have no authorized caller at all, so no token can ever pass.
export const denyAll = () => (req: Request, res: Response) => {
  res.status(401).json({ error: 'Unauthorized' })
}
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: tokenAlgorithm })
export const verify = (token: string) => {
  if (!token || isInvalidated(token)) {
    return false
  }
  try {
    jwt.verify(token, publicKey, { algorithms: [tokenAlgorithm] })
    return true
  } catch {
    return false
  }
}
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
    if (!token || !verify(utils.unquote(token))) {
      return undefined
    }
    return this.tokenMap[utils.unquote(token)]
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
  },
  invalidate: function (token: string) {
    const key = utils.unquote(token)
    const session = this.tokenMap[key]
    if (session && this.idMap[session.data.id] === key) {
      delete this.idMap[session.data.id]
    }
    delete this.tokenMap[key]
    invalidatedTokens.add(key)
  },
  invalidateAllFor: function (userId: number, exceptToken?: string) {
    const kept = exceptToken ? utils.unquote(exceptToken) : undefined
    for (const [token, session] of Object.entries(this.tokenMap)) {
      if (session.data.id === userId && token !== kept) {
        this.invalidate(token)
      }
    }
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

// z85 is an encoding, not a signature, so a bare encoded coupon lets anyone mint whatever
// discount they please. The key lives only in memory: coupons are valid for the current
// month and never have to survive a restart.
const couponKey = crypto.randomBytes(32)
const COUPON_SIGNATURE_LENGTH = 16

const couponSignature = (coupon: string) => {
  return crypto.createHmac('sha256', couponKey).update(coupon).digest('hex').substring(0, COUPON_SIGNATURE_LENGTH)
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon) + couponSignature(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon || coupon.length <= COUPON_SIGNATURE_LENGTH) {
    return undefined
  }
  const decoded = z85.decode(coupon.slice(0, -COUPON_SIGNATURE_LENGTH))?.toString()
  if (decoded && (hasValidFormat(decoded) != null) && coupon.slice(-COUPON_SIGNATURE_LENGTH) === couponSignature(decoded)) {
    const parts = decoded.split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
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
    allowed = allowed || url === allowedUrl // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

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

// Browser-driven pages (e.g. /support/logs) send the session as a cookie, not an Authorization header.
const tokenFrom = (req: Request) => req.cookies?.token || utils.jwtFrom(req)

// 'secure' is omitted on purpose: the shop is also served over plain HTTP.
export const sessionCookieOptions = { httpOnly: true, sameSite: 'strict' } as const

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(tokenFrom(req)) && decode(tokenFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(tokenFrom(req)) && decode(tokenFrom(req))
    if (decodedToken?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
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
      req.body.UserId = authenticatedUsers.get(utils.jwtFrom(req))!.data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

// The basket id is taken from the path, so a valid token alone says nothing about who owns that row.
export const isBasketOwner = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
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

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = tokenFrom(req)
  if (token && !isInvalidated(token)) {
    jwt.verify(token, publicKey, { algorithms: [tokenAlgorithm] }, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token, sessionCookieOptions)
        }
      }
    })
  }
  next()
}
