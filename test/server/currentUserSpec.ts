/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { retrieveLoggedInUser } from '../../routes/currentUser'
import { authenticatedUsers, authorize, decode } from '../../lib/insecurity'
import type { UserModel } from 'models/user'
const expect = chai.expect
chai.use(sinonChai)

describe('currentUser', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { cookies: {}, query: {} }
    res = { json: sinon.spy() }
  })

  it('should return neither ID nor email if no cookie was present in the request headers', () => {
    req.cookies.token = ''

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined } })
  })

  it('should return ID and email of user belonging to cookie from the request', () => {
    req.cookies.token = authorize({ data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } })
    req.query.callback = undefined
    authenticatedUsers.put(
      req.cookies.token,
      { data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )
    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } })
  })

  it('does not expose password hashes through the fields parameter', () => {
    req.cookies.token = authorize({ data: { id: 1, email: 'admin@juice-sh.op', password: 'sensitive' } })
    req.query.fields = 'id,password,totpSecret'
    authenticatedUsers.put(req.cookies.token, { data: { id: 1, email: 'admin@juice-sh.op', password: 'sensitive', totpSecret: 'sensitive' } as unknown as UserModel })

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: 1 } })
  })

  it('does not include password hashes or second-factor secrets in user tokens', () => {
    const token = authorize({ data: { id: 1, email: 'admin@juice-sh.op', password: 'sensitive', totpSecret: 'sensitive' } })
    const payload = decode(token)

    expect(payload.data).to.deep.equal({ id: 1, email: 'admin@juice-sh.op' })
  })
})
