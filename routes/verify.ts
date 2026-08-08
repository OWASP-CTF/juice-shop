/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'
import jwt from 'jsonwebtoken'
import config from 'config'
import jws from 'jws'

import { products, challenges, retrieveBlueprintChallengeFile } from '../data/datacache'
import type { Product as ProductConfig } from '../lib/config.types'
import { type Challenge, type Product } from '../data/types'
import * as challengeUtils from '../lib/challengeUtils'
import { ComplaintModel } from '../models/complaint'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const emptyUserRegistration = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.emptyUserRegistration, () => {
    return req.body && req.body.email === '' && req.body.password === ''
  })
  if (req.body && (req.body.email === '' || req.body.password === '' || req.body.email == null || req.body.password == null)) {
    res.status(400).send(res.__('Email and password are required.'))
    return
  }
  next()
}

export const forgedFeedbackChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  const user = security.authenticatedUsers.from(req)
  const userId = user?.data ? user.data.id : undefined
  challengeUtils.solveIf(challenges.forgedFeedbackChallenge, () => {
    return req.body?.UserId && req.body.UserId != userId // eslint-disable-line eqeqeq
  })
  req.body.UserId = userId ?? null
  next()
}

export const captchaBypassChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  const now = Date.now()
  const times: number[] = req.app.locals.captchaBypassReqTimes ?? []
  // Block the 10-in-20s CAPTCHA bypass pattern without calling solve().
  if (times.length >= 9 && (now - times[times.length - 9]) <= 20000) {
    res.status(429).send(res.__('Too many requests. Please try again later.'))
    return
  }
  times.push(now)
  req.app.locals.captchaBypassReqTimes = times.slice(-20)
  next()
}

export const registerAdminChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.registerAdminChallenge, () => {
    return req.body && req.body.role === security.roles.admin
  })
  if (req.body) {
    // Do not allow clients to self-assign privileged roles at registration.
    req.body.role = security.roles.customer
  }
  next()
}

export const passwordRepeatChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.passwordRepeatChallenge, () => { return req.body && req.body.passwordRepeat !== req.body.password })
  if (req.body && req.body.passwordRepeat !== req.body.password) {
    res.status(400).send(res.__('Passwords do not match.'))
    return
  }
  next()
}

export const accessControlChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  const { url } = req
  const uiBypassed = req.header('sec-fetch-dest') === 'document' || !req.header('referer')
  challengeUtils.solveIf(challenges.scoreBoardChallenge, () => { return utils.endsWith(url, '/1px.png') }, false, uiBypassed)
  // web3-sandbox / token-sale routes no longer expose these markers
  challengeUtils.solveIf(challenges.adminSectionChallenge, () => { return utils.endsWith(url, '/19px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.privacyPolicyChallenge, () => { return utils.endsWith(url, '/81px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.extraLanguageChallenge, () => { return utils.endsWith(url, '/tlh_AA.json') })
  challengeUtils.solveIf(challenges.retrieveBlueprintChallenge, () => { return utils.endsWith(url, retrieveBlueprintChallengeFile ?? undefined) })
  challengeUtils.solveIf(challenges.securityPolicyChallenge, () => { return utils.endsWith(url, '/security.txt') })
  challengeUtils.solveIf(challenges.missingEncodingChallenge, () => { return utils.endsWith(url.toLowerCase(), '%e1%93%9a%e1%98%8f%e1%97%a2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg') })
  challengeUtils.solveIf(challenges.accessLogDisclosureChallenge, () => { return url.match(/access\.log(0-9-)*/) })
  next()
}

export const errorHandlingChallenge = () => (err: unknown, req: Request, { statusCode }: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.errorHandlingChallenge, () => { return err && (statusCode === 200 || statusCode > 401) })
  next(err)
}

export const jwtChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.jwtUnsignedChallenge)) {
    jwtChallenge(challenges.jwtUnsignedChallenge, req, 'none', /jwtn3d@/)
  }
  if (utils.isChallengeEnabled(challenges.jwtForgedChallenge) && challengeUtils.notSolved(challenges.jwtForgedChallenge)) {
    jwtChallenge(challenges.jwtForgedChallenge, req, 'HS256', /rsa_lord@/)
  }
  next()
}

export const serverSideChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (req.query.key === 'tRy_H4rd3r_n0thIng_iS_Imp0ssibl3') {
    if (challengeUtils.notSolved(challenges.sstiChallenge) && req.app.locals.abused_ssti_bug === true) {
      challengeUtils.solve(challenges.sstiChallenge)
      res.status(204).send()
      return
    }

    if (challengeUtils.notSolved(challenges.ssrfChallenge) && req.app.locals.abused_ssrf_bug === true) {
      challengeUtils.solve(challenges.ssrfChallenge)
      res.status(204).send()
      return
    }
  }
  next()
}

function jwtChallenge (challenge: Challenge, req: Request, algorithm: string, email: string | RegExp) {
  const token = utils.jwtFrom(req)
  if (token) {
    const decoded = jws.decode(token) ? jwt.decode(token) : null

    if (decoded === null || typeof decoded === 'string') {
      return
    }

    jwt.verify(token, security.publicKey, { algorithms: ['RS256'] }, (err: jwt.VerifyErrors | null) => {
      if (err === null) {
        challengeUtils.solveIf(challenge, () => {
          return hasAlgorithm(token, algorithm) && hasEmail(decoded as { data: { email: string } }, email)
        })
      }
    })
  }
}

function hasAlgorithm (token: string, algorithm: string) {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
  return token && header && header.alg === algorithm
}

function hasEmail (token: { data: { email: string } }, email: string | RegExp) {
  return token?.data?.email?.match(email)
}

async function checkPatternInFeedbackAndComplaints (
  challenge: Challenge,
  fieldCriteria: any
): Promise<void> {
  const feedbackCheck = FeedbackModel.findAndCountAll({
    where: { comment: fieldCriteria }
  }).then(({ count }: { count: number }) => {
    if (count > 0) {
      challengeUtils.solve(challenge)
    }
  }).catch(() => {
    throw new Error('Unable to retrieve feedback details. Please try again')
  })

  const complaintCheck = ComplaintModel.findAndCountAll({
    where: { message: fieldCriteria }
  }).then(({ count }: { count: number }) => {
    if (count > 0) {
      challengeUtils.solve(challenge)
    }
  }).catch(() => {
    throw new Error('Unable to retrieve complaint details. Please try again')
  })

  await Promise.all([feedbackCheck, complaintCheck])
}

export const databaseRelatedChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.changeProductChallenge) && products.osaft) {
    changeProductChallenge(products.osaft)
  }
  if (challengeUtils.notSolved(challenges.feedbackChallenge)) {
    feedbackChallenge()
  }
  if (challengeUtils.notSolved(challenges.knownVulnerableComponentChallenge)) {
    knownVulnerableComponentChallenge()
  }
  if (challengeUtils.notSolved(challenges.weirdCryptoChallenge)) {
    weirdCryptoChallenge()
  }
  if (challengeUtils.notSolved(challenges.typosquattingNpmChallenge)) {
    typosquattingNpmChallenge()
  }
  if (challengeUtils.notSolved(challenges.typosquattingAngularChallenge)) {
    typosquattingAngularChallenge()
  }
  if (challengeUtils.notSolved(challenges.hiddenImageChallenge)) {
    hiddenImageChallenge()
  }
  // Supply-chain disclosure patterns removed — reporting the known eslint-scope
  // incident no longer auto-solves; credentials/artifacts are considered remediated.
  if (challengeUtils.notSolved(challenges.dlpPastebinDataLeakChallenge)) {
    dlpPastebinDataLeakChallenge()
  }
  if (challengeUtils.notSolved(challenges.csafChallenge)) {
    csafChallenge()
  }
  if (challengeUtils.notSolved(challenges.leakedApiKeyChallenge)) {
    leakedApiKeyChallenge()
  }
  next()
}

function changeProductChallenge (osaft: Product) {
  let urlForProductTamperingChallenge: string | null = null
  void osaft.reload().then(() => {
    for (const product of config.get<ProductConfig[]>('products')) {
      if (product.urlForProductTamperingChallenge !== undefined) {
        urlForProductTamperingChallenge = product.urlForProductTamperingChallenge
        break
      }
    }
    if (urlForProductTamperingChallenge) {
      if (!utils.contains(osaft.description, `${urlForProductTamperingChallenge}`)) {
        if (utils.contains(osaft.description, `<a href="${config.get<string>('challenges.overwriteUrlForProductTamperingChallenge')}" target="_blank">`)) {
          challengeUtils.solve(challenges.changeProductChallenge)
        }
      }
    }
  })
}

function feedbackChallenge () {
  FeedbackModel.findAndCountAll({ where: { rating: 5 } }).then(({ count }: { count: number }) => {
    if (count === 0) {
      challengeUtils.solve(challenges.feedbackChallenge)
    }
  }).catch(() => {
    throw new Error('Unable to retrieve feedback details. Please try again')
  })
}

function knownVulnerableComponentChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.knownVulnerableComponentChallenge,
    { [Op.or]: knownVulnerableComponents() }
  )
}

function knownVulnerableComponents () {
  // Vulnerable library versions remediated in developer artifacts;
  // do not auto-solve on historical version reports.
  return [
    {
      [Op.and]: [
        { [Op.like]: '%__remediated_sanitize_html__%' },
        { [Op.like]: '%__never__%' }
      ]
    }
  ]
}

function weirdCryptoChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.weirdCryptoChallenge,
    { [Op.or]: weirdCryptos() }
  )
}

function weirdCryptos () {
  return [
    { [Op.like]: '%z85%' },
    { [Op.like]: '%base85%' },
    { [Op.like]: '%hashids%' },
    { [Op.like]: '%md5%' },
    { [Op.like]: '%base64%' }
  ]
}

function typosquattingNpmChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.typosquattingNpmChallenge,
    { [Op.like]: '%epilogue-js%' }
  )
}

function typosquattingAngularChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.typosquattingAngularChallenge,
    { [Op.like]: '%ngy-cookie%' }
  )
}

function hiddenImageChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.hiddenImageChallenge,
    { [Op.like]: '%pickle rick%' }
  )
}

function supplyChainAttackChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.supplyChainAttackChallenge,
    { [Op.or]: eslintScopeVulnIds() }
  )
}

function eslintScopeVulnIds () {
  return [
    { [Op.like]: '%eslint-scope/issues/39%' },
    { [Op.like]: '%npm:eslint-scope:20180712%' }
  ]
}

function dlpPastebinDataLeakChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.dlpPastebinDataLeakChallenge,
    { [Op.and]: dangerousIngredients() }
  )
}

function csafChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.csafChallenge,
    { [Op.like]: '%' + config.get<string>('challenges.csafHashValue') + '%' }
  )
}

function leakedApiKeyChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.leakedApiKeyChallenge,
    { [Op.like]: '%6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie%' }
  )
}

function dangerousIngredients () {
  return config.get<ProductConfig[]>('products')
    .flatMap((product) => product.keywordsForPastebinDataLeakChallenge)
    .filter(Boolean)
    .map((keyword) => {
      return { [Op.like]: `%${keyword}%` }
    })
}
