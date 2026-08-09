/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

const configuredPrivateKey = process.env.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n')
const configuredPublicKey = process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n')
if ((configuredPrivateKey && !configuredPublicKey) || (!configuredPrivateKey && configuredPublicKey)) {
  throw new Error('JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be configured together')
}
const generatedKeys = configuredPrivateKey && configuredPublicKey
  ? null
  : crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  })
export const publicKey = configuredPublicKey ?? generatedKeys?.publicKey ?? ''
const privateKey = configuredPrivateKey ?? generatedKeys?.privateKey ?? ''

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
  remove: (token: string) => void
  removeByUserId: (userId: number) => void
}

/* MD5 is a broken hash and unsuitable for storing credentials. Both the
   password setter and every comparison go through this function, so moving to
   SHA-256 keeps them consistent. */
export const hash = (data: string) => crypto.createHash('sha256').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const decode = (token: string) => { return jws.decode(token)?.payload }
export const verify = (token?: string) => {
  if (!token) {
    return false
  }
  try {
    const decodedToken = decode(token)
    const expiresAt = typeof decodedToken === 'object' && decodedToken !== null ? decodedToken.exp : undefined
    return jws.verify(token, 'RS256', publicKey) && typeof expiresAt === 'number' && expiresAt > Math.floor(Date.now() / 1000)
  } catch {
    return false
  }
}

export const isAuthorized = () => (req: Request, res: Response, next: NextFunction) => {
  const token = utils.jwtFrom(req)
  if (token && authenticatedUsers.get(token)) {
    next()
  } else {
    res.status(401).json({ error: 'Authentication required' })
  }
}

export const denyAll = () => (_req: Request, res: Response) => {
  res.status(401).json({ error: 'Access denied' })
}

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
    const previousToken = this.idMap[user.data.id]
    if (previousToken && previousToken !== token) {
      delete this.tokenMap[previousToken]
    }
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    if (!token) {
      return undefined
    }
    const rawToken = utils.unquote(token)
    const user = this.tokenMap[rawToken]
    if (!user) {
      return undefined
    }
    try {
      if (!verify(rawToken)) {
        this.remove(rawToken)
        return undefined
      }
      return user
    } catch {
      this.remove(rawToken)
      return undefined
    }
  },
  tokenOf: function (user: UserModel) {
    const token = user ? this.idMap[user.id] : undefined
    return token && this.get(token) ? token : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  },
  remove: function (token: string) {
    const rawToken = utils.unquote(token)
    const user = this.tokenMap[rawToken]
    delete this.tokenMap[rawToken]
    if (user && this.idMap[user.data.id] === rawToken) {
      delete this.idMap[user.data.id]
    }
  },
  removeByUserId: function (userId: number) {
    const token = this.idMap[userId]
    if (token) {
      this.remove(token)
    }
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

/* z85 is an encoding, not a signature, so anyone could mint a coupon for an
   arbitrary discount by encoding the expected string. Coupons now carry an
   HMAC that only the server can produce. */
const couponSignature = (payload: string) => crypto.createHmac('sha256', privateKey).update(payload).digest('hex').substring(0, 32)

export const generateCoupon = (discount: number, date = new Date()) => {
  const payload = utils.toMMMYY(date) + '-' + discount
  return Buffer.from(payload).toString('hex') + couponSignature(payload)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon || coupon.length <= 32) {
    return undefined
  }
  const signature = coupon.substring(coupon.length - 32)
  const payloadHex = coupon.substring(0, coupon.length - 32)
  if (!/^[0-9a-fA-F]*$/.test(payloadHex)) {
    return undefined
  }
  const payload = Buffer.from(payloadHex, 'hex').toString('utf8')
  if (signature !== couponSignature(payload) || hasValidFormat(payload) == null) {
    return undefined
  }
  const parts = payload.split('-')
  if (utils.toMMMYY(new Date()) === parts[0]) {
    return parseInt(parts[1])
  }
}

/* hashids obfuscates, it does not authenticate: anyone could craft a continue
   code that restores arbitrary challenge ids. Progress codes now carry an HMAC,
   and stay alphanumeric so the existing format check still accepts them. */
const progressSignature = (namespace: string, payloadHex: string) => crypto.createHmac('sha256', privateKey).update(namespace + ':' + payloadHex).digest('hex').substring(0, 32)

export const encodeProgress = (namespace: string, ids: number[]) => {
  const payloadHex = Buffer.from(ids.join('.')).toString('hex')
  return payloadHex + progressSignature(namespace, payloadHex)
}

export const decodeProgress = (namespace: string, code?: string): number[] => {
  if (!code || code.length <= 32) {
    return []
  }
  const signature = code.substring(code.length - 32)
  const payloadHex = code.substring(0, code.length - 32)
  if (!/^[0-9a-fA-F]+$/.test(payloadHex) || signature !== progressSignature(namespace, payloadHex)) {
    return []
  }
  return Buffer.from(payloadHex, 'hex').toString('utf8')
    .split('.')
    .map(Number)
    .filter((id) => Number.isInteger(id))
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
    const user = authenticatedUsers.from(req)
    if (user?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = authenticatedUsers.from(req)
    if (user?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const user = authenticatedUsers.from(req)
  return user?.data?.role === roles.deluxe && user.data.deluxeToken && user.data.deluxeToken === deluxeToken(user.data.email)
}

export const isCustomer = (req: Request) => {
  return authenticatedUsers.from(req)?.data?.role === roles.customer
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
  /* A signed JWT is not enough to recreate a server-side session. Tokens are
     removed from authenticatedUsers on password changes and newer logins; adding
     them back here made revocation ineffective. */
  if (token && authenticatedUsers.get(token) !== undefined) {
    res.cookie('token', token, { httpOnly: true, sameSite: 'strict' })
  }
  next()
}
