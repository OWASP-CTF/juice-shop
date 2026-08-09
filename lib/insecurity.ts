/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

/* The RSA private key that signs every session token was a literal in this file, so it shipped in
   the repository, in every image built from it and in every fork - and the matching public half is
   served from /encryptionkeys. Anyone who read the source could mint a token for any account,
   including an administrator, without ever touching a password. A key is configuration, not code:
   the pair is taken from the environment, and when nothing is configured the shop generates one at
   boot. The public half is written where it has always been published, so verification, the
   /encryptionkeys listing and the JWT detectors all behave exactly as before. */
const jwtKeyPair = (() => {
  const configuredPrivate = process.env.JWT_PRIVATE_KEY
  const configuredPublic = process.env.JWT_PUBLIC_KEY
  if (configuredPrivate && configuredPublic) {
    return { privateKey: configuredPrivate, publicKey: configuredPublic }
  }
  const generated = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' } // matches the PKCS#1 the signer has always been given
  })
  if (fs) {
    try {
      fs.writeFileSync('encryptionkeys/jwt.pub', generated.publicKey)
    } catch { /* the published copy is best-effort; verification uses the in-memory key */ }
  }
  return generated
})()

export const publicKey = jwtKeyPair.publicKey
const privateKey = jwtKeyPair.privateKey

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

/* The key that protects every stored recovery answer was a literal in this file, so it shipped in
   the repository, in every image built from it and in every fork. Anyone holding it can precompute
   the hash of a guessed answer offline, which reduces account recovery to a rainbow table. It is
   configuration, not code: it comes from the environment, and when nothing is configured the shop
   derives one at boot so there is nothing left to leak. */
const hmacKey = process.env.HMAC_KEY ?? crypto.randomBytes(32).toString('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacKey).update(data).digest('hex')

/* MD5 is a fast, unsalted digest: a disclosed user table is cracked at billions of guesses a
   second, and two accounts choosing the same password are visibly identical. Passwords are stored
   with scrypt under a per-account salt. Records written before this change still verify against
   the old scheme, so nobody is locked out and they upgrade the next time the password is set. */
const SCRYPT_KEYLEN = 64
const scryptHash = (plainText: string, salt: string) =>
  crypto.scryptSync(plainText, salt, SCRYPT_KEYLEN).toString('hex')

export const hashPassword = (plainText: string) => {
  const salt = crypto.randomBytes(16).toString('hex')
  return `scrypt$${salt}$${scryptHash(plainText, salt)}`
}

export const verifyPassword = (plainText: string, stored: string | undefined) => {
  if (!stored) {
    return false
  }
  if (stored.startsWith('scrypt$')) {
    const [, salt, expected] = stored.split('$')
    const actual = scryptHash(plainText ?? '', salt)
    return actual.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))
  }
  return hash(plainText ?? '') === stored
}

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

/* The shop only ever issues RS256 tokens, so that is the only signature algorithm it accepts.
   Taking the algorithm from the token itself lets an attacker sign one with HMAC using the RSA
   *public* key - which is published under /encryptionkeys and therefore no secret at all. */
export const jwtAlgorithm = 'RS256'

export const hasExpectedAlgorithm = (token?: string) => {
  if (!token) {
    return false
  }
  try {
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
    return header?.alg === jwtAlgorithm
  } catch (error: unknown) {
    return false
  }
}

/* Drops a token whose header asks for any other algorithm before anything downstream gets to look
   at it. The request then simply counts as unauthenticated, which is what a signature the shop
   never issued is worth - and endpoints that do require a session answer 401 as they always do. */
export const denyForgedTokenAlgorithm = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (utils.jwtFrom(req) && !hasExpectedAlgorithm(utils.jwtFrom(req))) {
      delete req.headers.authorization
    }
    if (req.cookies?.token && !hasExpectedAlgorithm(req.cookies.token)) {
      delete req.cookies.token
    }
    next()
  }
}

// Single source of truth for the password policy: registration and the change-password route
// both enforce it, so the rule cannot drift between the two entry points. Follows NIST
// SP 800-63B - length is the control that matters, plus a blocklist of known-weak values, and
// deliberately no composition rules.
export const PASSWORD_MIN_LENGTH = 12
const WEAK_PASSWORDS = new Set([
  'admin123', 'password', 'password1', 'passw0rd', 'welcome1', 'letmein',
  'qwertyuiop', '123456789012', 'administrator', 'juiceshop', 'owasp', 'changeme'
])

export const validatePasswordPolicy = (password: unknown): string | null => {
  if (typeof password !== 'string' || password === '') {
    return 'Password cannot be empty.'
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`
  }
  if (password.length > 128) {
    return 'Password must be at most 128 characters long.'
  }
  if (WEAK_PASSWORDS.has(password.toLowerCase())) {
    return 'Password is too common. Please choose a less predictable one.'
  }
  if (new Set(password).size < 4) {
    return 'Password is not varied enough. Please choose a less predictable one.'
  }
  return null
}

export const isAuthorized = () => {
  const dropForgedAlgorithm = denyForgedTokenAlgorithm()
  const authorizeToken = expressjwt({ secret: publicKey, algorithms: [jwtAlgorithm] })
  return (req: Request, res: Response, next: NextFunction) => {
    dropForgedAlgorithm(req, res, () => { authorizeToken(req, res, next) })
  }
}
export const sameOriginOnly = () => (req: Request, res: Response, next: NextFunction) => {
  const source = req.headers.origin ?? req.headers.referer
  if (!source) {
    res.status(403).json({ error: 'A same-origin request is required' })
    return
  }
  try {
    if (new URL(source).host !== req.headers.host) {
      res.status(403).json({ error: 'Cross-origin request blocked' })
      return
    }
  } catch {
    res.status(403).json({ error: 'Invalid request origin' })
    return
  }
  next()
}
export const denyAll = () => expressjwt({ secret: '' + Math.random(), algorithms: [jwtAlgorithm] })
/* The whole user record was signed into the token, so the stored password hash and the TOTP
   secret travelled to the client on every login and sat in browser storage. Only the claims the
   shop actually reads are signed. */
const claimsFor = (user: any) => {
  if (!user || typeof user !== 'object' || !('data' in user)) {
    return user
  }
  /* data is a Sequelize instance on the login path, where the attributes live behind toJSON()
     rather than on the object itself - spreading it directly drops role and id, which then
     disappear from the token and every role check fails. */
  const raw = (user as any).data
  const plain = (raw && typeof raw.toJSON === 'function') ? raw.toJSON() : { ...(raw ?? {}) }
  const { password, totpSecret, ...safeData } = plain
  return { ...(user as any), data: safeData }
}
export const authorize = (user = {}) => jwt.sign(claimsFor(user), privateKey, { expiresIn: '6h', algorithm: jwtAlgorithm })
export const verify = (token: string) => hasExpectedAlgorithm(token) ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
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
    const cleaned = utils.unquote(token)
    if (!verify(cleaned)) {
      return undefined
    }
    return this.tokenMap[cleaned]
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
    if (token && verify(token)) {
      this.put(token, user)
    }
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

/* A coupon was nothing but z85 of "MMMYY-DD". z85 is an encoding, not a signature, so anybody who
   noticed the shape could hand-mint themselves a 99% discount without the shop ever issuing one.
   Coupons now carry a short tag over their own contents, keyed on the configured secret, and a
   coupon whose tag does not match is not a coupon this shop issued. The tag is fixed length so the
   encoded part is still recovered unambiguously, and the shop's own coupons - including the ones
   the chatbot hands out - keep working exactly as before. */
const COUPON_TAG_LENGTH = 10

const couponTag = (plainCoupon: string) => hmac('coupon:' + plainCoupon).slice(0, COUPON_TAG_LENGTH)

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon) + couponTag(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon || coupon.length <= COUPON_TAG_LENGTH) {
    return undefined
  }
  const tag = coupon.slice(-COUPON_TAG_LENGTH)
  const encoded = coupon.slice(0, -COUPON_TAG_LENGTH)
  let decoded
  try {
    decoded = z85.decode(encoded)
  } catch {
    return undefined
  }
  if (!decoded) {
    return undefined
  }
  const plain = decoded.toString()
  if (couponTag(plain) !== tag) {
    return undefined
  }
  if (hasValidFormat(plain) != null) {
    const parts = plain.split('-')
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
    allowed = allowed || url === allowedUrl
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

/* Keying this on the signing key meant the entitlement was forgeable by anyone who had the key,
   and tied a membership check to a value whose whole job is signing. It uses the configured secret. */
export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', hmacKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

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
  if (token && hasExpectedAlgorithm(token)) {
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
