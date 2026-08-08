/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import config from 'config'
import sinonChai from 'sinon-chai'
import { challenges, products, setRetrieveBlueprintChallengeFile } from '../../data/datacache'
import type { Product, Challenge } from 'data/types'
import type { Product as ProductConfig } from '../../lib/config.types'
import * as security from '../../lib/insecurity'
import { type UserModel } from 'models/user'
import * as verify from '../../routes/verify'
const expect = chai.expect

chai.use(sinonChai)

describe('verify', () => {
  let req: any
  let res: any
  let next: any
  let save: any
  let err: any

  beforeEach(() => {
    req = { body: {}, headers: {}, header: sinon.stub().returns(undefined) }
    res = { json: sinon.spy() }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
  })

  describe('"forgedFeedbackChallenge"', () => {
    beforeEach(() => {
      security.authenticatedUsers.put('token12345', {
        data: {
          id: 42,
          email: 'test@juice-sh.op'
        } as unknown as UserModel
      })
      challenges.forgedFeedbackChallenge = { solved: false, save } as unknown as Challenge
    })

    it('keeps the authenticated user ID when writing feedback', () => {
      req.body.UserId = 42
      req.headers = { authorization: 'Bearer token12345' }

      verify.forgedFeedbackChallenge()(req, res, next)

      expect(req.body.UserId).to.equal(42)
      expect(challenges.forgedFeedbackChallenge.solved).to.equal(false)
      expect(next.calledOnce).to.equal(true)
    })

    it('assigns the authenticated user ID when none is supplied', () => {
      req.body.UserId = undefined
      req.headers = { authorization: 'Bearer token12345' }

      verify.forgedFeedbackChallenge()(req, res, next)

      expect(req.body.UserId).to.equal(42)
      expect(challenges.forgedFeedbackChallenge.solved).to.equal(false)
    })

    it('overwrites another user ID supplied by an authenticated user', () => {
      req.body.UserId = 1
      req.headers = { authorization: 'Bearer token12345' }

      verify.forgedFeedbackChallenge()(req, res, next)

      expect(req.body.UserId).to.equal(42)
      expect(challenges.forgedFeedbackChallenge.solved).to.equal(false)
    })

    it('removes a user ID supplied by an anonymous user', () => {
      req.body.UserId = 1
      req.headers = {}

      verify.forgedFeedbackChallenge()(req, res, next)

      expect(req.body.UserId).to.equal(null)
      expect(challenges.forgedFeedbackChallenge.solved).to.equal(false)
    })
  })

  describe('accessControlChallenges', () => {
    it('"scoreBoardChallenge" is solved when the 1px.png transpixel is requested', () => {
      challenges.scoreBoardChallenge = { solved: false, save } as unknown as Challenge
      req.url = 'http://juice-sh.op/public/images/padding/1px.png'

      verify.accessControlChallenges()(req, res, next)

      expect(challenges.scoreBoardChallenge.solved).to.equal(true)
    })

    it('"adminSectionChallenge" is solved when the 19px.png transpixel is requested', () => {
      challenges.adminSectionChallenge = { solved: false, save } as unknown as Challenge
      req.url = 'http://juice-sh.op/public/images/padding/19px.png'

      verify.accessControlChallenges()(req, res, next)

      expect(challenges.adminSectionChallenge.solved).to.equal(true)
    })

    it('"tokenSaleChallenge" remains unsolved when the legacy 56px.png transpixel is requested', () => {
      challenges.tokenSaleChallenge = { solved: false, save } as unknown as Challenge
      req.url = 'http://juice-sh.op/public/images/padding/56px.png'

      verify.accessControlChallenges()(req, res, next)

      expect(challenges.tokenSaleChallenge.solved).to.equal(false)
    })

    it('"web3SandboxChallenge" remains unsolved when the legacy 11px.png transpixel is requested', () => {
      challenges.web3SandboxChallenge = { solved: false, save } as unknown as Challenge
      req.url = 'http://juice-sh.op/public/images/padding/11px.png'

      verify.accessControlChallenges()(req, res, next)

      expect(challenges.web3SandboxChallenge.solved).to.equal(false)
    })

    it('"extraLanguageChallenge" is solved when the Klingon translation file is requested', () => {
      challenges.extraLanguageChallenge = { solved: false, save } as unknown as Challenge
      req.url = 'http://juice-sh.op/public/i18n/tlh_AA.json'

      verify.accessControlChallenges()(req, res, next)

      expect(challenges.extraLanguageChallenge.solved).to.equal(true)
    })

    it('"retrieveBlueprintChallenge" is solved when the blueprint file is requested', () => {
      challenges.retrieveBlueprintChallenge = { solved: false, save } as unknown as Challenge
      setRetrieveBlueprintChallengeFile('test.dxf')
      req.url = 'http://juice-sh.op/public/images/products/test.dxf'

      verify.accessControlChallenges()(req, res, next)

      expect(challenges.retrieveBlueprintChallenge.solved).to.equal(true)
    })

    it('"missingEncodingChallenge" is solved when the crazy cat photo is requested', () => {
      challenges.missingEncodingChallenge = { solved: false, save } as unknown as Challenge
      req.url = 'http://juice-sh.op/public/images/uploads/%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg'

      verify.accessControlChallenges()(req, res, next)

      expect(challenges.missingEncodingChallenge.solved).to.equal(true)
    })

    it('"accessLogDisclosureChallenge" is not solved by a URL resembling a server access log', () => {
      challenges.accessLogDisclosureChallenge = { solved: false, save } as unknown as Challenge
      req.url = 'http://juice-sh.op/support/logs/access.log.2019-01-15'

      verify.accessControlChallenges()(req, res, next)

      expect(challenges.accessLogDisclosureChallenge.solved).to.equal(false)
    })
  })

  describe('serverSideChallenges', () => {
    it('does not solve the SSTI challenge from a stale application flag', () => {
      challenges.sstiChallenge = { solved: false, save } as unknown as Challenge
      challenges.ssrfChallenge = { solved: false, save } as unknown as Challenge
      req.query = { key: 'tRy_H4rd3r_n0thIng_iS_Imp0ssibl3' }
      req.app = { locals: { abused_ssti_bug: true } }
      res.status = sinon.stub().returns(res)
      res.send = sinon.spy()

      verify.serverSideChallenges()(req, res, next)

      expect(challenges.sstiChallenge.solved).to.equal(false)
      expect(res.status.called).to.equal(false)
      expect(next.calledOnce).to.equal(true)
    })
  })

  describe('"errorHandlingChallenge"', () => {
    beforeEach(() => {
      challenges.errorHandlingChallenge = { solved: false, save } as unknown as Challenge
    })

    it('is solved when an error occurs on a response with OK 200 status code', () => {
      res.statusCode = 200
      err = new Error()

      verify.errorHandlingChallenge()(err, req, res, next)

      expect(challenges.errorHandlingChallenge.solved).to.equal(true)
    })

    describe('is solved when an error occurs on a response with error', () => {
      const httpStatus = [402, 403, 404, 500]
      httpStatus.forEach(statusCode => {
        it(`${statusCode} status code`, () => {
          res.statusCode = statusCode
          err = new Error()

          verify.errorHandlingChallenge()(err, req, res, next)

          expect(challenges.errorHandlingChallenge.solved).to.equal(true)
        })
      })
    })

    it('is not solved when no error occurs on a response with OK 200 status code', () => {
      res.statusCode = 200
      err = undefined

      verify.errorHandlingChallenge()(err, req, res, next)

      expect(challenges.errorHandlingChallenge.solved).to.equal(false)
    })

    describe('is not solved when no error occurs on a response with error', () => {
      const httpStatus = [401, 402, 404, 500]
      httpStatus.forEach(statusCode => {
        it(`${statusCode} status code`, () => {
          res.statusCode = statusCode
          err = undefined

          verify.errorHandlingChallenge()(err, req, res, next)

          expect(challenges.errorHandlingChallenge.solved).to.equal(false)
        })
      })
    })

    it('should pass occurred error on to next route', () => {
      res.statusCode = 500
      err = new Error()

      verify.errorHandlingChallenge()(err, req, res, next)

      expect(next).to.have.been.calledWith(err)
    })
  })

  describe('databaseRelatedChallenges', () => {
    describe('"changeProductChallenge"', () => {
      beforeEach(() => {
        challenges.changeProductChallenge = { solved: false, save } as unknown as Challenge
        products.osaft = { reload () { return { then (cb: any) { cb() } } } } as unknown as Product
      })

      it(`is solved when the link in the O-Saft product goes to ${config.get<string>('challenges.overwriteUrlForProductTamperingChallenge')}`, () => {
        products.osaft.description = `O-Saft, yeah! <a href="${config.get<string>('challenges.overwriteUrlForProductTamperingChallenge')}" target="_blank">More...</a>`

        verify.databaseRelatedChallenges()(req, res, next)

        expect(challenges.changeProductChallenge.solved).to.equal(true)
      })

      it('is not solved when the link in the O-Saft product is changed to an arbitrary URL', () => {
        products.osaft.description = 'O-Saft, nooo! <a href="http://arbitrary.url" target="_blank">More...</a>'

        verify.databaseRelatedChallenges()(req, res, next)

        expect(challenges.changeProductChallenge.solved).to.equal(false)
      })

      it('is not solved when the link in the O-Saft product remained unchanged', () => {
        let urlForProductTamperingChallenge = null
        for (const product of config.get<ProductConfig[]>('products')) {
          if (product.urlForProductTamperingChallenge !== undefined) {
            urlForProductTamperingChallenge = product.urlForProductTamperingChallenge
            break
          }
        }
        products.osaft.description = `Vanilla O-Saft! <a href="${urlForProductTamperingChallenge}" target="_blank">More...</a>`

        verify.databaseRelatedChallenges()(req, res, next)

        expect(challenges.changeProductChallenge.solved).to.equal(false)
      })
    })
  })
})
