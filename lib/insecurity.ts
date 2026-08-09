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

// The signing key used to be written out here, so every copy of the source could mint a token
// asserting any account and any role - the published public half at /encryptionkeys/jwt.pub made
// the pair complete. The pair is generated once per process instead. JWT_PRIVATE_KEY /
// JWT_PUBLIC_KEY override it for deployments that need tokens to survive a restart; without them
// a restart invalidates outstanding tokens, which is already true of the in-memory session map.
const generatedKeyPair = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
})

const privateKey: string = process.env.JWT_PRIVATE_KEY ?? generatedKeyPair.privateKey
export const publicKey: string = process.env.JWT_PUBLIC_KEY ?? generatedKeyPair.publicKey

// Whatever key is actually in use has to be the one that is published, otherwise every client
// that verifies against the downloaded file breaks. The write is best-effort: encryptionkeys/ is
// not group-writable in the container image, and a failure here must not stop the application -
// the in-memory key still governs either way.
try {
  fs.writeFileSync('encryptionkeys/jwt.pub', publicKey, 'utf8')
} catch {
  /* read-only deployment: the shipped jwt.pub stays as it is and only in-process verification applies */
}

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

// Kept as-is on purpose: this digest is also the gravatar hash rendered into the profile page and
// the prefix of every order id, neither of which is a secret and both of which are md5 by
// definition. Password storage does NOT use it anymore - see hashPassword/verifyPassword below.
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// The key this HMAC carried travelled with the source, and security answers are short guessable
// strings, so anybody holding a copy could invert the whole SecurityAnswers table offline. Answers
// are written (by the seeder) and read (by the reset flow) inside one process, so a per-process key
// preserves the flow exactly while removing the offline attack. SECURITY_ANSWER_KEY pins it where a
// deployment needs answers to survive a restart.
const hmacKey: string = process.env.SECURITY_ANSWER_KEY ?? crypto.randomBytes(32).toString('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacKey).update(data).digest('hex')

const SCRYPT_KEYLEN = 64
const PASSWORD_PREFIX = 'scrypt'

const timingSafeEqualString = (left: string, right: string) => {
  const leftBuffer = Buffer.from(left)
  const rightBuffer = Buffer.from(right)
  if (leftBuffer.length !== rightBuffer.length) {
    return false
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer)
}

// A password digest has to be salted and slow. The stored form carries its own salt, so no schema
// change is needed - the column still holds a single string.
export const hashPassword = (clearTextPassword: string) => {
  const salt = crypto.randomBytes(16)
  const derived = crypto.scryptSync(String(clearTextPassword ?? ''), salt, SCRYPT_KEYLEN)
  return `${PASSWORD_PREFIX}$${salt.toString('hex')}$${derived.toString('hex')}`
}

// Accepts the salted digest above and, as a fallback, the legacy unsalted md5, so a row written by
// any path that still calls hash() authenticates instead of locking the account out.
export const verifyPassword = (clearTextPassword: string, storedPassword?: string | null) => {
  if (!storedPassword) {
    return false
  }
  const candidate = String(clearTextPassword ?? '')
  if (!storedPassword.startsWith(`${PASSWORD_PREFIX}$`)) {
    return timingSafeEqualString(hash(candidate), storedPassword)
  }
  const parts = storedPassword.split('$')
  const saltHex = parts[1]
  const expectedHex = parts[2]
  if (!saltHex || !expectedHex) {
    return false
  }
  try {
    const derived = crypto.scryptSync(candidate, Buffer.from(saltHex, 'hex'), SCRYPT_KEYLEN)
    return timingSafeEqualString(derived.toString('hex'), expectedHex)
  } catch {
    return false
  }
}

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
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

// Reads the token's own expiry claim. A payload that cannot be parsed is not treated as expired -
// the signature checks elsewhere are what reject junk; this only enforces lifetime.
const isExpiredToken = (token: string) => {
  try {
    const payload = jws.decode(token)?.payload
    const claims = typeof payload === 'string' ? JSON.parse(payload) : payload
    return typeof claims?.exp === 'number' && claims.exp * 1000 <= Date.now()
  } catch {
    return false
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
    if (!token) {
      return undefined
    }
    const normalizedToken = utils.unquote(token)
    const user = this.tokenMap[normalizedToken]
    if (user === undefined) {
      return undefined
    }
    // The map is otherwise only ever added to, so a token that has passed its own expiry kept
    // resolving to a live session for as long as the process ran. Expiry is enforced on read.
    if (isExpiredToken(normalizedToken)) {
      this.remove(normalizedToken)
      return undefined
    }
    return user
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

// A coupon was nothing but z85 of "MMMYY-discount" - a format containing no secret - so any
// customer could mint themselves a 99% coupon without ever asking the shop for one. The payload is
// now authenticated with a per-process key. The shop hands out coupons exactly as before and
// redeems every coupon it handed out; a coupon this instance did not mint no longer decodes to a
// discount. COUPON_KEY pins the key where coupons must survive a restart.
const couponKey: string = process.env.COUPON_KEY ?? crypto.randomBytes(32).toString('hex')

// z85 requires a payload length that is a multiple of four. "MMMYY-DD" is eight characters and the
// tag adds "-" plus seven, making every coupon exactly sixteen. Padding the discount to two digits
// also repairs a latent crash: a single-digit discount produced a seven-character payload, which
// made z85.encode throw.
const COUPON_TAG_LENGTH = 7

const couponTag = (payload: string) =>
  crypto.createHmac('sha256', couponKey).update(payload).digest('hex').substring(0, COUPON_TAG_LENGTH)

export const generateCoupon = (discount: number, date = new Date()) => {
  const boundedDiscount = Math.max(0, Math.min(99, Math.trunc(Number(discount) || 0)))
  const payload = `${utils.toMMMYY(date)}-${String(boundedDiscount).padStart(2, '0')}`
  return z85.encode(`${payload}-${couponTag(payload)}`)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  // The coupon arrives straight off the request path, so a value z85 cannot decode has to be
  // answered with "no discount" rather than an exception out of the handler.
  let decoded = ''
  try {
    decoded = z85.decode(coupon)?.toString() ?? ''
  } catch {
    return undefined
  }
  if (hasValidFormat(decoded) == null) {
    return undefined
  }
  const parts = decoded.split('-')
  const payload = `${parts[0]}-${parts[1]}`
  if (!timingSafeEqualString(parts[2], couponTag(payload))) {
    return undefined
  }
  if (utils.toMMMYY(new Date()) !== parts[0]) {
    return undefined
  }
  return parseInt(parts[1], 10)
}

// Anchored, and the tag is part of the shape, so a decoded string that merely contains something
// coupon-shaped no longer passes.
function hasValidFormat (coupon: string) {
  return coupon.match(/^(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}-[0-9a-f]{7}$/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
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
  if (token) {
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
