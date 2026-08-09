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
  remove: (token?: string) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

// Single source of truth for the password policy: registration and the change-password
// route both enforce it, so the rule cannot drift between the two entry points.
//
// Follows NIST SP 800-63B - length is the control that matters, and a blocklist of
// known-weak values does the rest. Deliberately no composition rules (no "must contain
// a symbol"): they push users toward predictable substitutions without adding entropy.
export const PASSWORD_MIN_LENGTH = 12
export const PASSWORD_MAX_LENGTH = 128

const WEAK_PASSWORDS = new Set([
  'admin123', 'password', 'password1', 'passw0rd', 'welcome1', 'letmein',
  'qwertyuiop', '123456789012', 'administrator', 'juiceshop', 'owasp',
  'changeme', 'iloveyou', 'monkey123', 'football', 'baseball'
])

// The only user attributes allowed to leave the server. Withholding by omission rather
// than by excluding a denylist means a column added later is private until somebody
// deliberately lists it here - the password hash, the TOTP secret and the deluxe token
// are all absent because nothing added them.
//
// Single source of truth: /rest/user/whoami, the password change, the password reset and
// the login-IP update all answered with a user record, and three of them returned the
// whole model, hash included.
export const DISCLOSABLE_USER_FIELDS = ['id', 'email', 'lastLoginIp', 'profileImage', 'role']

export const publicUserView = (user: any, fields: string[] = DISCLOSABLE_USER_FIELDS) => {
  const source = user?.dataValues ?? user?.data ?? user
  const view: Record<string, unknown> = {}
  if (source == null) {
    return view
  }
  for (const field of fields) {
    if (DISCLOSABLE_USER_FIELDS.includes(field) && source[field] !== undefined) {
      view[field] = source[field]
    }
  }
  return view
}

export const validatePasswordPolicy = (password: unknown): string | null => {
  if (typeof password !== 'string' || password === '') {
    return 'Password cannot be empty.'
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return `Password must be at most ${PASSWORD_MAX_LENGTH} characters long.`
  }
  const normalized = password.toLowerCase()
  if (WEAK_PASSWORDS.has(normalized)) {
    return 'Password is too common. Please choose a less predictable one.'
  }
  // A password consisting of one repeated character clears any length bar while
  // carrying almost no entropy.
  if (new Set(password).size < 4) {
    return 'Password is not varied enough. Please choose a less predictable one.'
  }
  return null
}

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
  // hasAcceptedAlgorithm already pinned the header to RS256, so the algorithm passed
  // here is a literal, never token-supplied, input.
  type VerifyFn = (token: string, algorithm: string, secret: string) => boolean
  return (jws.verify as VerifyFn)(token, 'RS256', publicKey)
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
  remove: function (token?: string) {
    if (!token) return
    const normalizedToken = utils.unquote(token)
    const user = this.tokenMap[normalizedToken]
    if (user && this.idMap[user.data.id] === normalizedToken) {
      delete this.idMap[user.data.id]
    }
    delete this.tokenMap[normalizedToken]
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

// A continue code is a bearer claim over the whole progress state, and the salts it was
// derived from travelled with the source, so anyone could mint a code asserting any
// progress they liked and have it applied. The salts are drawn per process instead: a
// code this instance handed out still applies back to it, one minted anywhere else does
// not decode to anything.
export const continueCodeSalts = {
  challenges: crypto.randomBytes(24).toString('hex'),
  findIt: crypto.randomBytes(24).toString('hex'),
  fixIt: crypto.randomBytes(24).toString('hex')
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
    const token = sessionTokenFrom(req)
    const decodedToken = token && verify(token) && decode(token)
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
// A session arrives as a bearer token on XHR, but as the `token` cookie on the requests the
// browser makes itself - page navigations and every asset fetch. Reading only the header meant
// the role checks below refused a signed-in administrator the moment the request came from the
// browser rather than from application code, which is exactly how the privileged pages and the
// log browser are actually reached.
export const sessionTokenFrom = (req: Request) => utils.jwtFrom(req) || req.cookies?.token

export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = sessionTokenFrom(req)
    const decodedToken = token && verify(token) && decode(token)
    if (decodedToken?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

// The profile and avatar endpoints act on the session cookie alone, so a page on another
// site could post to them on a logged-in visitor's behalf. A request that declares an
// origin has to declare this one; a request with no origin at all (a direct API call) is
// left to the ordinary authorisation checks.
export const sameOriginOnly = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const source = req.headers.origin ?? req.headers.referer
    if (source !== undefined) {
      try {
        if (new URL(source).host !== req.headers.host) {
          res.status(403).json({ error: 'Cross-origin request blocked' })
          return
        }
      } catch {
        res.status(403).json({ error: 'Invalid request origin' })
        return
      }
    }
    next()
  }
}

export const isDeluxe = (req: Request) => {
  const token = sessionTokenFrom(req)
  const decodedToken = token && verify(token) && decode(token)
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const token = sessionTokenFrom(req)
  const decodedToken = token && verify(token) && decode(token)
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
  // jsonwebtoken 0.4.0 also reads the algorithm out of the header, so a forged token
  // would be admitted to the session map here even though the guards reject it elsewhere.
  if (token && hasAcceptedAlgorithm(token)) {
    // The accepted algorithm is pinned here as well as in the header check above, so the
    // verifier can never be talked into treating the public key as an HMAC secret.
    jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          // SameSite=Strict keeps the session cookie off cross-site requests, so a page on
          // another origin cannot ride it. HttpOnly is deliberately not set: the client
          // clears this cookie from script on logout, and a cookie it could no longer
          // remove would keep the server-side session alive after sign-out.
          res.cookie('token', token, { sameSite: 'strict', secure: req.secure })
        }
      }
    })
  }
  next()
}
