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
// This key must never be the well-known key that ships in the public project history - anyone
// holding it could mint arbitrary self-signed session tokens (e.g. claiming the admin role)
// without ever needing to exploit anything else. Keep it in sync with encryptionkeys/jwt.pub.
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXQIBAAKBgQCgNgO8dpn2fchn3rAvkb5Kms+hY+fBQHXg7NT+LT2rFgAvGhyE\r\nNwMS24okGnXOGoSV/3aXdyPVqxedz8HxALYKMn3xbUO6c5nQPYV+XLb0rx3uMm6p\r\nNyfvQNYqpnyw5PNUZ02shLMTDgbtO3GIE303jAeVs4JJE7yTOT1HooYWFQIDAQAB\r\nAoGAer9ntWmZJMXSWeLAUnHzve1Gz3xgACyHJEHQHr5C1WYR1gTHfHU5oaUa/fZX\r\n9AVVOCd2kS3zAq4Hdh3Llf7ZeVgJIwFmaI2ech26pn4tAem0cNvzljTbOxJBcFf4\r\nbIC6lkKSrIkkqO9+uB7OVGdFfyStpb125FVApBxhMVGkzjECQQDS2caRGK6nJzoS\r\nSMLn0MmAMfsCuP6a48+LaXSIjpceMePUWyG9ie5hBCIw1qeO60EDaiMZG5QhOnIq\r\nFDjdvZh/AkEAwoRRTy4ydvFQN9tfVbhNnTfh5AGuukcu6ijjwB2tJ5F/7KdgR15m\r\ni8/fWHmzZjHLkuOrsGxJFc33OhUFx/QnawJANnfvpdf8dk3Z4JNPVldHVoiS0Xc8\r\nvoKPQPJzGjvLqg81TcxlAPO60vEgbAFns7HuT5WBj6DiOVtB1sD2l8G8vQJBAIhT\r\nSdUPkIix6UGseq1OBP9ZyfQNhdLBzsyHqc7cPZ3MqHZIe/6o13/HSUXtzWCjJ4Sk\r\nEZEM40/n0Qwg7bNMl08CQQDFOF0IUCC5IbJ4fi1JYQl7+HPu8Iisp3BG2i0cmKtR\r\nbeiEh1LiJdRd5Vjhz6gpXesmnBl4vrZ9gN3euh2WL294\r\n-----END RSA PRIVATE KEY-----'

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
// Must not be the well-known secret from the public project history - anyone holding it could
// verify guesses against a leaked security-answer hash offline without ever needing to know
// this value from the running instance.
export const hmac = (data: string) => crypto.createHmac('sha256', 'bT2RwLLmE7dVWeAtritE4uSwntnFNyI').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

/* The shop only ever issues RS256-signed tokens, so that is the only signature algorithm any
   verification path may accept. Leaving the algorithm to be read from the token itself (as
   express-jwt/jsonwebtoken/jws all do by default) lets an attacker sign a token with HMAC
   (HS256) using the RSA *public* key as the "secret" - which is published under
   /encryptionkeys and is therefore not a secret at all - and have it accepted as valid,
   including claiming an arbitrary role such as admin. */
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

/* Strips a token whose header asks for any algorithm other than RS256 before anything
   downstream looks at it. The request then simply counts as unauthenticated - which is what a
   signature the shop never issued is worth - and endpoints that require a session answer 401
   as they always do for a missing/invalid token. */
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

export const isAuthorized = () => {
  const dropForgedAlgorithm = denyForgedTokenAlgorithm()
  const authorizeToken = expressJwt(({ secret: publicKey, algorithms: [jwtAlgorithm] }) as any)
  return (req: Request, res: Response, next: NextFunction) => {
    dropForgedAlgorithm(req, res, () => { authorizeToken(req, res, next) })
  }
}
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: jwtAlgorithm })
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
// The outdated cryptocurrency donation addresses have been removed from the allowlist entirely -
// keeping stale/unverified third-party addresses in an allowlist is itself a liability.
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
