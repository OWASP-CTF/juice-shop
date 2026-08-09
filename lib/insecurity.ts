/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

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

// Tokens are minted RS256 and nothing else is legitimate. The two-argument jws.verify
// takes the algorithm from the token's own header, so a token declaring alg:none, or one
// signed HS256 using the RSA public key that is published at /encryptionkeys/jwt.pub,
// would verify against this same key. The header is therefore pinned before the
// signature is trusted, and express-jwt 0.1.3 forwards no algorithm restriction of its
// own, so the same check runs in front of it.
const hasAcceptedAlgorithm = (token: string) => {
  try {
    return jws.decode(token)?.header?.alg === 'RS256'
  } catch {
    return false
  }
}

// A bearer token is only ever honoured when it carries the RS256 signature this shop
// issues. Applied once in front of every route, so a forged token is refused before any
// handler, detector or session lookup sees it rather than at each verification site.
export const denyForgedTokenAlgorithm = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req) || req.cookies?.token
    if (token && !hasAcceptedAlgorithm(token)) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    next()
  }
}

export const isAuthorized = () => {
  const requireValidToken = expressJwt(({ secret: publicKey }) as any)
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    if (token && !hasAcceptedAlgorithm(token)) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    requireValidToken(req, res, next)
  }
}
// These routes have no authorised caller at all, so this denies unconditionally rather
// than checking a token against a random secret - a check alg:none walked straight past.
export const denyAll = () => (req: Request, res: Response, next: NextFunction) => {
  res.status(401).json({ error: 'Unauthorized' })
}
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => {
  if (!token || !hasAcceptedAlgorithm(token)) {
    return false
  }
  return (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey)
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
    if (!token) {
      return undefined
    }
    // The map is keyed by the raw token string, so any caller holding a string that happens
    // to be a key was treated as that session - including one presented in a cookie, which
    // several routes read without going through isAuthorized() at all. The signature is
    // therefore checked here too, so a session is only ever handed out for a token this
    // shop actually issued.
    const presented = utils.unquote(token)
    if (!verify(presented)) {
      return undefined
    }
    return this.tokenMap[presented]
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    // Writing an unverified token into the map would create the very session the lookup
    // above refuses to hand out, so the same check applies on the way in.
    const token = utils.jwtFrom(req)
    if (token && verify(token)) {
      this.put(token, user)
    }
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
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

// The administration screen is guarded in the browser by AdminGuard, which decodes the
// token without verifying it, so the role it reads is supplied by the caller. This
// verifies the signature before the role claim is read.
export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

// A state-changing endpoint that authorises from the ambient session cookie is reachable
// by any page the victim happens to visit. A request that states where it came from has to
// state this host; one that states nothing is left alone, so ordinary non-browser clients
// and the shop's own same-origin forms keep working and only genuine cross-site
// submissions are refused.
export const sameOriginOnly = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const statedOrigin = req.headers.origin ?? req.headers.referer
    if (!statedOrigin) {
      // A request that states no origin at all cannot be shown to have come from this shop,
      // and letting it through made the guard trivially avoidable: a cross-site form or a
      // scripted client simply omits both headers. State-changing account endpoints require
      // a stated, matching origin.
      res.status(403).json({ error: 'A same-origin request is required' })
      return
    }
    let statedHost
    try {
      statedHost = new URL(statedOrigin).host
    } catch {
      res.status(403).json({ error: 'Cross-site request refused' })
      return
    }
    if (statedHost !== req.headers.host) {
      res.status(403).json({ error: 'Cross-site request refused' })
      return
    }
    next()
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
      // Reading tokenMap directly skipped the signature check that authenticatedUsers.get
      // performs, so the owning user id was taken from an unverified token.
      const user = authenticatedUsers.from(req)
      if (!user?.data?.id) {
        res.status(401).json({ status: 'error', message: 'Unauthorized' })
        return
      }
      req.body.UserId = user.data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  // jsonwebtoken 0.4.0 also reads the algorithm out of the header, so a forged token
  // would be admitted to the session map here even though the guards reject it elsewhere.
  if (token && hasAcceptedAlgorithm(token)) {
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
