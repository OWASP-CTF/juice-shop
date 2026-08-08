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

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'
const totpSecretEncryptionKey = crypto.createHmac('sha256', privateKey).update('juice-shop:totp-secret:v1').digest()
const totpSecretEncryptionVersion = 'v1'
const configuredCouponSecret = process.env.JUICE_SHOP_COUPON_SECRET
if (configuredCouponSecret !== undefined && Buffer.byteLength(configuredCouponSecret, 'utf8') < 32) {
  throw new Error('JUICE_SHOP_COUPON_SECRET must contain at least 32 bytes')
}
const couponSigningKey = configuredCouponSecret === undefined
  ? crypto.randomBytes(32)
  : crypto.createHash('sha256').update(configuredCouponSecret).digest()
const couponVersion = 'v1'
const maximumCouponDiscount = 75
const couponPattern = /^(v1):((?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\d{2}):(\d{2})\.([A-Za-z0-9_-]{43})$/

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

export const encryptTotpSecret = (secret?: string) => {
  if (!secret) {
    return ''
  }

  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', totpSecretEncryptionKey, iv)
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  return [totpSecretEncryptionVersion, iv.toString('base64url'), authTag.toString('base64url'), ciphertext.toString('base64url')].join(':')
}

export const decryptTotpSecret = (encryptedSecret?: string) => {
  if (!encryptedSecret) {
    return ''
  }

  const [version, encodedIv, encodedAuthTag, encodedCiphertext, ...unexpected] = encryptedSecret.split(':')
  if (version !== totpSecretEncryptionVersion || !encodedIv || !encodedAuthTag || !encodedCiphertext || unexpected.length > 0) {
    throw new Error('Invalid encrypted TOTP secret')
  }

  const iv = Buffer.from(encodedIv, 'base64url')
  const authTag = Buffer.from(encodedAuthTag, 'base64url')
  if (iv.length !== 12 || authTag.length !== 16) {
    throw new Error('Invalid encrypted TOTP secret')
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', totpSecretEncryptionKey, iv)
  decipher.setAuthTag(authTag)
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(encodedCiphertext, 'base64url')),
    decipher.final()
  ])
  return plaintext.toString('utf8')
}

const withoutTotpSecret = <T>(payload: T): T => {
  const candidate = payload as any
  if (!candidate?.data || typeof candidate.data !== 'object') {
    return payload
  }

  const data = typeof candidate.data.toJSON === 'function' ? candidate.data.toJSON() : { ...candidate.data }
  delete data.totpSecret
  return { ...candidate, data }
}

const jwtAlgorithm = 'RS256'
const verifyJws = jws.verify as unknown as ((signature: string, secretOrKey: string) => boolean)

const hasExpectedJwtAlgorithm = (token?: string) => {
  if (!token) {
    return false
  }
  try {
    return jws.decode(token)?.header?.alg === jwtAlgorithm
  } catch (error) {
    return false
  }
}

const verifiedJwtPayload = (token?: string) => {
  if (!token || !hasExpectedJwtAlgorithm(token)) {
    return undefined
  }

  try {
    if (!verifyJws(token, publicKey)) {
      return undefined
    }

    const payload = jws.decode(token)?.payload
    if (payload?.exp && Math.round(Date.now()) / 1000 >= payload.exp) {
      return undefined
    }
    return payload
  } catch (error) {
    return undefined
  }
}

const jwtAuthentication = (secret: string) => {
  const authenticate = expressJwt({ secret, algorithms: [jwtAlgorithm] })
  return (req: Request, res: Response, next: NextFunction) => {
    if (!hasExpectedJwtAlgorithm(utils.jwtFrom(req))) {
      res.status(401).json({ status: 'error', message: 'Invalid authentication token' })
      return
    }
    authenticate(req, res, next)
  }
}

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => jwtAuthentication(publicKey)
export const denyAll = () => jwtAuthentication('' + Math.random())
export const authorize = (user = {}) => jwt.sign(withoutTotpSecret(user), privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token?: string) => verifiedJwtPayload(token) !== undefined
export const decode = (token?: string) => verifiedJwtPayload(token)

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
    const safeUser = withoutTotpSecret(user)
    this.tokenMap[token] = safeUser
    this.idMap[safeUser.data.id] = token
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

export const generateCoupon = (discount: number, date = new Date()) => {
  if (!Number.isInteger(discount) || discount < 1 || discount > maximumCouponDiscount) {
    throw new RangeError(`Coupon discount must be an integer between 1 and ${maximumCouponDiscount}`)
  }
  if (Number.isNaN(date.getTime())) {
    throw new RangeError('Coupon date must be valid')
  }

  const payload = `${couponVersion}:${utils.toMMMYY(date)}:${discount.toString().padStart(2, '0')}`
  const signature = crypto.createHmac('sha256', couponSigningKey).update(payload).digest('base64url')
  return `${payload}.${signature}`
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }

  const match = coupon.match(couponPattern)
  if (!match) {
    return undefined
  }

  const [, version, validity, encodedDiscount, encodedSignature] = match
  const discount = Number(encodedDiscount)
  if (version !== couponVersion || !Number.isInteger(discount) || discount < 1 || discount > maximumCouponDiscount) {
    return undefined
  }

  const payload = `${version}:${validity}:${encodedDiscount}`
  const expectedSignature = crypto.createHmac('sha256', couponSigningKey).update(payload).digest()
  const providedSignature = Buffer.from(encodedSignature, 'base64url')
  if (providedSignature.length !== expectedSignature.length || providedSignature.toString('base64url') !== encodedSignature) {
    return undefined
  }
  if (!crypto.timingSafeEqual(providedSignature, expectedSignature)) {
    return undefined
  }

  return utils.toMMMYY(new Date()) === validity ? discount : undefined
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
    const decoded = decode(token)
    if (decoded && authenticatedUsers.get(token) === undefined) {
      authenticatedUsers.put(token, decoded)
      res.cookie('token', token)
    }
  }
  next()
}
