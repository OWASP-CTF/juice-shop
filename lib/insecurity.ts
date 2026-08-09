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

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
/* The signing key is 2048 bit: 1024 bit RSA is below current guidance and is rejected
   outright by maintained JWT libraries. */
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAk7E0joCcrtu8Xn72xQozEtx2ugh2DzJYSYw7asBpOyO2MA2n\r\nETBIE1nTbL/W2w4yy8Qukj8UpUZNm20htwBn5ysXryuQwV04hQKaEZwV2GZ/fIPA\r\nq5igDiUxITLvV9/SWrTmdsh4BZ7qyztqQyenpXb0a4S4tc7KiOa7o75puESOWlGm\r\nQk5yXvWJf6+z2VxFVAsBxYh0U3AQ4CRlcYRGzGnadAjQakHwj24z9sny4lAkjpCG\r\nJCi2J2H9nBR38+zrP4tP3Hwq7OggAX+UawQKeQLCWbPDZs3lJKtu/9QY+EAvjBE+\r\ny65YjW9VEFy4ByzbEsaMFvofAeo7iFqVn47h/QIDAQABAoIBABWREN2mRjr6d11N\r\nKPfI74BXlTbBOYwqi93hjmOeST+LjXUi6TyHUl8RBOCiettuDVjYAvz0HS2tQHPr\r\n0bqJYqLNFh5MPE0gMbqqkJj1s/LvtLoX+zCTjvvBzpTMfUrVsj/wnp7F01DuzdZz\r\njKbVyZNN9Y8lyFs0ITswhkH48jMoBswlxbcJtBYldKjuvIM1ak8aXCgkGH6TPOvW\r\nAAcBNrXO82y4xGwntGpKGif9USNaOrNAyBet4bGFoLTpTQIlDl6mTWiA47bQb7E3\r\ntkm1u/BZM6ZqGILWLe4l0sMamNB4x5z4GAqk4XbZFVxk6EXYodwi5OweDQlYHV9H\r\nn0OTHrkCgYEAzMhj76o7EFYKFZXcqwGsr/cGNQhWzIzQCYt5jk3HPJctN38mrWd4\r\ng54yPYB9DElPaE4H0PE4XPH3FQFE1mdJEkbTn4DLwoUaN7VxnUEgQMP5MPNZqa0X\r\n99vCjbcGciLtCopNmdOyquQu4O00SYfksdEvvZDNYI6G+ApiUgjIH0cCgYEAuKF7\r\nYuXGJtBUFAexnI8WbKK2R+JDWNg745397ivkDKRCb2QNY1jrVGK/nZhk8iLInKWp\r\n8vrRSA0K+d74dD/PwfllItPllN9SCkd4LWAIH8mNEoHAQwC9qfju2QU/0vFRAJRq\r\nwMTrQDTR6n6VSY/KEXs+ExWwzk2V6NMrZV6JfpsCgYEAr9XtQbAI0SkftZMdjFR+\r\nxAU29jh312GdjGSPdmpAhj1E3R83xbNP3qvqdbarKO6V2XkO6xEFFYHKZ+XUBslf\r\nC+t28MF1tEv3zBfnO2DdYd8kTCzYM4JmTzQKpQaf6UcmBGPm6AvHoUcXHZlvySd/\r\nblOxS3NXde5L5BV+gPP7aicCgYBPC4Oh0bHGCEcW1DxsRK5bEEZt/CbNMLZjOs7u\r\nWwgliWWP/wvkTrthw2058Xa2W8H7nsll55AWAs+CLr28N12hND7ibEnMNNgQ4oxH\r\nEOgpg8bL95TymqyYyqSncSHkE8CUOPaDVUtKj9KXTF5pwg/G8DahQRYTHRBjP5VC\r\nrvi6pQKBgGbEc/wXAOpUa+VR2xtUwqMeNMSnVsjPvZQM1obaNCkoe7qtRIQpNd6K\r\nz5GUvLPXgTzf3FsICWcA2eGdoOiuZDijhEurdU+6gfd5iyGeXeKKKUGlrHvOXSjN\r\nuppKM//9Gw6o7R7gw5CXaADrbTqnbRbz5aHK0sOXlmTcTzGY7AXP\r\n-----END RSA PRIVATE KEY-----'

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

/* Session tokens are signed RS256 and the matching key is public, so verification has to pin the
   algorithm: without it a token could be HMAC-signed with the published public key, or presented
   unsigned as `alg: none`, and still be accepted. */
const jwtSigningAlgorithm = 'RS256'

export const isAuthorized = () => expressjwt({ secret: publicKey, algorithms: [jwtSigningAlgorithm] })
export const denyAll = () => expressjwt({ secret: '' + Math.random(), algorithms: ['HS256'] })
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: jwtSigningAlgorithm })
const jwtHeaderOf = (token: unknown) => {
  if (typeof token !== 'string') {
    return undefined
  }
  const encodedHeader = token.split('.')[0]
  if (!encodedHeader) {
    return undefined
  }
  try {
    const header: unknown = JSON.parse(Buffer.from(encodedHeader, 'base64').toString('utf8'))
    if (header === null || typeof header !== 'object') {
      return undefined
    }
    return header as { alg?: string }
  } catch {
    return undefined
  }
}

export const hasExpectedJwtAlgorithm = (token: unknown) => jwtHeaderOf(token)?.alg === jwtSigningAlgorithm

/* Rejects any request presenting a token which declares a signing algorithm outside the
   allow-list, before it reaches middleware that would try to verify or decode it. */
export const enforceJwtAlgorithm = () => (req: Request, res: Response, next: NextFunction) => {
  for (const token of [req.cookies?.token, utils.jwtFrom(req)]) {
    const header = jwtHeaderOf(token)
    if (header !== undefined && header.alg !== jwtSigningAlgorithm) {
      res.status(401).json({ error: 'Unsupported JWT signing algorithm' })
      return
    }
  }
  next()
}

export const verify = (token: string) => {
  if (!token || !hasExpectedJwtAlgorithm(token)) {
    return false
  }
  try {
    if (!jws.verify(token, jwtSigningAlgorithm, publicKey)) {
      return false
    }
    /* A signature only says the token was issued here, never that it is still valid, so the
       expiry has to be enforced where the token is accepted. */
    const decoded = jws.decode(token)?.payload
    const payload = typeof decoded === 'string' ? JSON.parse(decoded) : decoded
    return typeof payload?.exp === 'number' && payload.exp > Math.floor(Date.now() / 1000)
  } catch {
    return false
  }
}
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
const SANITIZE_PASS_LIMIT = 25

export const sanitizeSecure = (html: string): string => {
  // Sanitising once can leave a payload behind when a stripped tag reveals another one,
  // so keep sanitising until the result stops changing. The pass limit turns a pathological
  // input into an empty string instead of unbounded work.
  let current = html
  for (let pass = 0; pass < SANITIZE_PASS_LIMIT; pass++) {
    const sanitized = sanitizeHtml(current)
    if (sanitized === current) {
      return sanitized
    }
    current = sanitized
  }
  return ''
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
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  return redirectAllowlist.has(url) // vuln-code-snippet vuln-line redirectChallenge
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

/* A session token may arrive as a bearer token (XHR) or as the `token` cookie
   (plain document and asset requests made by the browser itself). */
const sessionTokenFrom = (req: Request) => utils.jwtFrom(req) || req.cookies?.token

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
    jwt.verify(token, publicKey, { algorithms: [jwtSigningAlgorithm] }, (err: Error | null, decoded: any) => {
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
