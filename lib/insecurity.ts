/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

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

const configuredPrivateKey = process.env.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n')
const privateKey = configuredPrivateKey ?? crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
}).privateKey
export const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString()
const applicationHmacKey = process.env.APPLICATION_HMAC_KEY ?? crypto.createHash('sha256').update(privateKey).digest('hex')
export const authCookieOptions = {
  httpOnly: true,
  sameSite: 'strict' as const,
  secure: process.env.NODE_ENV === 'production'
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
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', applicationHmacKey).update(data).digest('hex')
export const hashPassword = (password: string) => {
  const salt = crypto.randomBytes(16)
  const derivedKey = crypto.scryptSync(password, salt, 32)
  return `${salt.toString('hex')}:${derivedKey.toString('hex')}`
}
export const verifyPassword = (password: string, storedPassword: string) => {
  const [saltHex, hashHex, ...extra] = storedPassword.split(':')
  if (extra.length !== 0 || !/^[0-9a-f]{32}$/i.test(saltHex) || !/^[0-9a-f]{64}$/i.test(hashHex)) {
    return false
  }
  const expected = Buffer.from(hashHex, 'hex')
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length)
  return crypto.timingSafeEqual(actual, expected)
}

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

const expectedJwtAlgorithm = 'RS256'

export const hasExpectedJwtAlgorithm = (token?: string) => {
  if (!token) {
    return false
  }
  try {
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString())
    return header?.alg === expectedJwtAlgorithm
  } catch {
    return false
  }
}

export const isAuthorized = () => {
  const verifyToken = expressJwt(({ secret: publicKey }) as any)
  return (req: Request, res: Response, next: NextFunction) => {
    if (!hasExpectedJwtAlgorithm(utils.jwtFrom(req))) {
      res.status(401).send()
      return
    }
    verifyToken(req, res, next)
  }
}
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: expectedJwtAlgorithm })
export const verify = (token: string) => hasExpectedJwtAlgorithm(token) ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
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

export const generateCoupon = (discount: number, date = new Date()) => {
  const payload = utils.toMMMYY(date) + '-' + discount.toString().padStart(2, '0')
  const coupon = payload + ':' + hmac(payload).slice(0, 15)
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  try {
    const decoded = z85.decode(coupon)?.toString()
    const match = decoded?.match(/^((?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-([0-9]{2})):([0-9a-f]{15})$/)
    if (match) {
      const [, payload, discountText, signature] = match
      const expectedSignature = hmac(payload).slice(0, 15)
      if (crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature)) && utils.toMMMYY(new Date()) === payload.slice(0, 5)) {
        const discount = Number(discountText)
        return discount >= 1 && discount <= 50 ? discount : undefined
      }
    }
  } catch {
    return undefined
  }
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
  return redirectAllowlist.has(url)
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    const decodedToken = verify(token) && decode(token)
    if (decodedToken?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxeUser = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (isDeluxe(req)) {
      next()
    } else {
      res.status(403).json({ error: 'Deluxe membership required' })
    }
  }
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
          res.cookie('token', token, authCookieOptions)
        }
      }
    })
  }
  next()
}
