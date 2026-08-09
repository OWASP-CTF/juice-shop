/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

/*
 * The only targets /redirect is still allowed to send visitors to.
 *
 * The former cryptocurrency donation addresses (blockchain.info,
 * explorer.dash.org and etherscan.io) have been retired and are therefore no
 * longer allowlisted: keeping stale third-party destinations reachable through
 * our own redirector means we keep vouching for addresses nobody owns or
 * monitors any more, which is exactly what an attacker needs to make a
 * malicious link look trustworthy.
 */
const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

const allowedProtocols = new Set(['http:', 'https:'])

function parseUrl (value: string) {
  try {
    return new URL(value)
  } catch {
    return undefined
  }
}

/*
 * Resolves the requested target to the exact allowlist entry it matches.
 *
 * The comparison is done against the parsed and normalized origin + path of
 * the URL and never against a substring of the raw parameter. Payloads that
 * merely embed an allowlisted URL - such as
 * https://evil.tld/?pwned=https://github.com/juice-shop/juice-shop - therefore
 * no longer pass the check.
 */
function resolveAllowedRedirect (toUrl: unknown): string | undefined {
  if (typeof toUrl !== 'string' || toUrl === '') {
    return undefined
  }
  const target = parseUrl(toUrl)
  if (target === undefined) {
    return undefined
  }
  if (!allowedProtocols.has(target.protocol)) {
    return undefined
  }
  if (target.username !== '' || target.password !== '') {
    return undefined
  }
  const normalized = `${target.origin}${target.pathname}`
  return redirectAllowlist.has(normalized) ? normalized : undefined
}

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string
    const allowedUrl = resolveAllowedRedirect(toUrl)
    if (allowedUrl !== undefined) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
      challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
      // Redirect to the canonical allowlist entry instead of the raw input so
      // that no attacker-controlled characters end up in the Location header.
      res.redirect(allowedUrl)
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
