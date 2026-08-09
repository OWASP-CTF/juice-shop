/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import packageJson from '../package.json'
import fs from 'node:fs'
import logger from './logger'
import config from 'config'
import download from 'download'
import crypto from 'node:crypto'
import clarinet from 'clarinet'
import type { Challenge } from 'data/types'

import isHeroku from './is-heroku'
import isDocker from './is-docker'
import isWindows from './is-windows'
export { default as isDocker } from './is-docker'
export { default as isWindows } from './is-windows'
// import isGitpod from 'is-gitpod') // FIXME Roll back to this when https://github.com/dword-design/is-gitpod/issues/94 is resolve
const isGitpod = () => false

const months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC']

export const queryResultToJson = <T>(
  data: T,
  status: string = 'success'
): { data: T, status: string } => {
  return {
    status,
    data
  }
}

export const isUrl = (url: string) => {
  return startsWith(url, 'http')
}

export const startsWith = (str: string, prefix: string) => str ? str.indexOf(prefix) === 0 : false

export const endsWith = (str?: string, suffix?: string) => (str && suffix) ? str.includes(suffix, str.length - suffix.length) : false

export const contains = (str: string, element: string) => str ? str.includes(element) : false // TODO Inline all usages as this function is not adding any functionality to String.includes

export const containsEscaped = function (str: string, element: string) {
  return contains(str, element.replace(/"/g, '\\"'))
}

export const containsOrEscaped = function (str: string, element: string) {
  return contains(str, element) || containsEscaped(str, element)
}

export const unquote = function (str: string) {
  if (str && startsWith(str, '"') && endsWith(str, '"')) {
    return str.substring(1, str.length - 1)
  } else {
    return str
  }
}

export const trunc = function (str: string, length: number) {
  str = str.replace(/(\r\n|\n|\r)/gm, '')
  return (str.length > length) ? str.substr(0, length - 1) + '...' : str
}

export const version = (module?: string) => {
  if (module) {
    // @ts-expect-error FIXME Ignoring any type issue on purpose
    return packageJson.dependencies[module]
  } else {
    return packageJson.version
  }
}

let cachedCtfKey: string | undefined
const getCtfKey = () => {
  if (!cachedCtfKey) {
    if (process.env.CTF_KEY !== undefined && process.env.CTF_KEY !== '') {
      cachedCtfKey = process.env.CTF_KEY
    } else {
      const data = fs.readFileSync('ctf.key', 'utf8')
      cachedCtfKey = data
    }
  }
  return cachedCtfKey
}
export const ctfFlag = (text: string) => {
  return crypto.createHmac('sha1', getCtfKey()).update(text).digest('hex')
}

export const toMMMYY = (date: Date) => {
  const month = date.getMonth()
  const year = date.getFullYear()
  return months[month] + year.toString().substring(2, 4)
}

export const toISO8601 = (date: Date) => {
  let day = '' + date.getDate()
  let month = '' + (date.getMonth() + 1)
  const year = date.getFullYear()

  if (month.length < 2) month = '0' + month
  if (day.length < 2) day = '0' + day

  return [year, month, day].join('-')
}

export const extractFilename = (url: string) => {
  let file = decodeURIComponent(url.substring(url.lastIndexOf('/') + 1))
  if (contains(file, '?')) {
    file = file.substring(0, file.indexOf('?'))
  }
  return file
}

export const downloadToFile = async (url: string, dest: string) => {
  try {
    const data = await download(url)
    fs.writeFileSync(dest, data)
  } catch (err) {
    logger.warn('Failed to download ' + url + ' (' + getErrorMessage(err) + ')')
  }
}

export const jwtFrom = ({ headers }: { headers: any }) => {
  if (headers?.authorization) {
    const parts = headers.authorization.split(' ')
    if (parts.length === 2) {
      const scheme = parts[0]
      const token = parts[1]

      if (/^Bearer$/i.test(scheme)) {
        return token
      }
    }
  }
  return undefined
}

export const randomHexString = (length: number): string => {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length)
}

export interface ChallengeEnablementStatus {
  enabled: boolean
  disabledBecause: string | null
}

type SafetyModeSetting = 'enabled' | 'disabled' | 'auto'

type isEnvironmentFunction = () => boolean

export function getChallengeEnablementStatus (challenge: Challenge,
  safetyModeSetting: SafetyModeSetting = config.get<SafetyModeSetting>('challenges.safetyMode'),
  isEnvironmentFunctions: {
    isDocker: isEnvironmentFunction
    isHeroku: isEnvironmentFunction
    isWindows: isEnvironmentFunction
    isGitpod: isEnvironmentFunction
  } = { isDocker, isHeroku, isWindows, isGitpod }): ChallengeEnablementStatus {
  if (!challenge?.disabledEnv) {
    return { enabled: true, disabledBecause: null }
  }

  if (safetyModeSetting === 'disabled') {
    return { enabled: true, disabledBecause: null }
  }

  if (challenge.disabledEnv?.includes('Docker') && isEnvironmentFunctions.isDocker()) {
    return { enabled: false, disabledBecause: 'Docker' }
  }
  if (challenge.disabledEnv?.includes('Heroku') && isEnvironmentFunctions.isHeroku()) {
    return { enabled: false, disabledBecause: 'Heroku' }
  }
  if (challenge.disabledEnv?.includes('Windows') && isEnvironmentFunctions.isWindows()) {
    return { enabled: false, disabledBecause: 'Windows' }
  }
  if (challenge.disabledEnv?.includes('Gitpod') && isEnvironmentFunctions.isGitpod()) {
    return { enabled: false, disabledBecause: 'Gitpod' }
  }
  if (challenge.disabledEnv && safetyModeSetting === 'enabled') {
    return { enabled: false, disabledBecause: 'Safety Mode' }
  }

  return { enabled: true, disabledBecause: null }
}
export function isChallengeEnabled (challenge: Challenge): boolean {
  const { enabled } = getChallengeEnablementStatus(challenge)
  return enabled
}

export const parseJsonCustom = (jsonString: string) => {
  const parser = clarinet.parser()
  const result: any[] = []
  parser.onkey = parser.onopenobject = (k: any) => {
    result.push({ key: k, value: null })
  }
  parser.onvalue = (v: any) => {
    result[result.length - 1].value = v
  }
  parser.write(jsonString)
  parser.close()
  return result
}

export const toSimpleIpAddress = (ipv6: string) => {
  if (startsWith(ipv6, '::ffff:')) {
    return ipv6.substr(7)
  } else if (ipv6 === '::1') {
    return '127.0.0.1'
  } else {
    return ipv6
  }
}

/**
 * Expands an IPv6 address (optionally with one embedded trailing IPv4 dotted-decimal
 * address, e.g. `::ffff:127.0.0.1`) into its 8 constituent 16-bit hex groups, resolving
 * `::` zero-run compression. Returns null if `ip` isn't a syntactically plausible IPv6
 * address. Internal helper for extractMappedIpv4Address.
 */
const expandIpv6Groups = (ip: string): string[] | null => {
  let working = ip
  const lastColon = working.lastIndexOf(':')
  if (lastColon !== -1) {
    const tail = working.substring(lastColon + 1)
    const dotted = tail.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
    if (dotted) {
      const octets = dotted.slice(1, 5).map(Number)
      if (octets.some((o) => o < 0 || o > 255)) return null
      const hi = ((octets[0] << 8) | octets[1]).toString(16)
      const lo = ((octets[2] << 8) | octets[3]).toString(16)
      working = working.substring(0, lastColon + 1) + hi + ':' + lo
    }
  }

  const doubleColonParts = working.split('::')
  if (doubleColonParts.length > 2) return null // an IPv6 address may contain at most one '::'

  let groups: string[]
  if (doubleColonParts.length === 2) {
    const head = doubleColonParts[0] === '' ? [] : doubleColonParts[0].split(':')
    const tail = doubleColonParts[1] === '' ? [] : doubleColonParts[1].split(':')
    const missing = 8 - head.length - tail.length
    if (missing < 1) return null // '::' must stand in for at least one zero group
    groups = [...head, ...Array(missing).fill('0'), ...tail]
  } else {
    groups = working.split(':')
  }

  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null
  return groups
}

/**
 * If `ip` is an IPv4-mapped (`::ffff:0:0/96`) or deprecated IPv4-compatible
 * (`::0.0.0.0/96`) IPv6 address - in either its dotted-decimal suffix form
 * (`::ffff:127.0.0.1`) or its canonical hex-group form (`::ffff:7f00:1`, the form
 * Node's URL parser normalizes bracketed IPv6-literal hosts to) - returns the embedded
 * IPv4 address in dotted-decimal notation. Returns null for any other IPv6 address,
 * including ordinary public addresses that merely *end* in two hex groups that happen
 * to look like a private IPv4 address - the leading 80 (or 96) bits must genuinely be
 * zero, checked structurally rather than via a suffix-only pattern match, so this can't
 * misfire on unrelated addresses. This closes an SSRF filter bypass where an attacker
 * wraps a blocked IPv4 address (e.g. 127.0.0.1) in IPv6 syntax to evade a naive
 * dotted-decimal-only check.
 */
export const extractMappedIpv4Address = (ip: string): string | null => {
  const groups = expandIpv6Groups(ip.toLowerCase())
  if (!groups) return null

  const isZero = (group: string) => parseInt(group, 16) === 0
  if (!groups.slice(0, 5).every(isZero)) return null // leading 80 bits must be zero

  const marker = parseInt(groups[5], 16)
  if (marker !== 0 && marker !== 0xffff) return null // 6th group: zero (compatible) or ffff (mapped)

  const hi = parseInt(groups[6], 16)
  const lo = parseInt(groups[7], 16)
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff].join('.')
}

/**
 * Checks whether the given IP address (IPv4, IPv6, or an IPv4 address embedded in
 * IPv6 syntax) falls into a private, loopback, link-local or otherwise
 * non-publicly-routable range. Used to block Server-Side Request Forgery (SSRF)
 * attacks against internal or local infrastructure. See CWE-918.
 */
export const isPrivateOrReservedIpAddress = (ip: string): boolean => {
  const ipv4Match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (ipv4Match) {
    const octets = ipv4Match.slice(1, 5).map(Number)
    if (octets.some((octet) => octet < 0 || octet > 255)) {
      return true // not a valid IP, treat as unsafe
    }
    const [a, b] = octets
    if (a === 127) return true // 127.0.0.0/8 loopback
    if (a === 0) return true // 0.0.0.0/8 "this" network
    if (a === 10) return true // 10.0.0.0/8 private
    if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12 private
    if (a === 192 && b === 168) return true // 192.168.0.0/16 private
    if (a === 169 && b === 254) return true // 169.254.0.0/16 link-local
    if (a === 100 && b >= 64 && b <= 127) return true // 100.64.0.0/10 carrier-grade NAT
    return false
  }

  const normalized = ip.toLowerCase()
  if (normalized === '::1') return true // IPv6 loopback
  if (normalized === '::') return true // IPv6 unspecified
  if (normalized.startsWith('fe80:') || normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true // fe80::/10 link-local
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true // fc00::/7 unique local

  // An IPv4 address wrapped in IPv6 syntax (e.g. `::ffff:127.0.0.1` or its
  // canonical hex-group form `::ffff:7f00:1`) must be judged by the IPv4 rules
  // above too, or it becomes a trivial SSRF filter bypass.
  const mappedIpv4 = extractMappedIpv4Address(normalized)
  if (mappedIpv4 && isPrivateOrReservedIpAddress(mappedIpv4)) {
    return true
  }

  return false
}

export const getErrorMessage = (error: unknown) => {
  if (error instanceof Error) return error.message
  return String(error)
}

export const matchesSystemIniFile = (text: string) => {
  const match = text.match(/; for 16-bit app support/gi)
  return match !== null && match.length >= 1
}

export const matchesEtcPasswdFile = (text: string) => {
  const match = text.match(/(\w*:\w*:\d*:\d*:\w*:.*)|(Note that this file is consulted directly)/gi)
  return match !== null && match.length >= 1
}

/**
 * Wrapper for asynchronous Express route handlers to ensure any rejected promises are caught and passed to the next() function.
 * TODO: Revisit the need for this wrapper once the project is migrated to Express 5 which supports async handlers natively.
 */
export const asyncHandler = (fn: (req: any, res: any, next: any) => Promise<any> | any) => (req: any, res: any, next: any) => {
  void Promise.resolve(fn(req, res, next)).catch(next)
}
