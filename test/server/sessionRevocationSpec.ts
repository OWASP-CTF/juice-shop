/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { type Request } from 'express'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'
import { saveLoginIp } from '../../routes/saveLoginIp'

const expect = chai.expect
chai.use(sinonChai)

describe('session revocation', () => {
  it('continues to refresh an active session cookie', () => {
    const user = { data: { id: 99000, role: security.roles.customer } as unknown as UserModel }
    const token = security.authorize(user)
    security.authenticatedUsers.put(token, user)

    const req = { cookies: { token }, headers: {} } as unknown as Request
    const res = { cookie: sinon.spy() } as any
    const next = sinon.spy()

    security.updateAuthenticatedUsers()(req, res, next)

    expect(security.authenticatedUsers.get(token)).to.equal(user)
    expect(res.cookie).to.have.been.calledWith('token', token, { httpOnly: true, sameSite: 'strict' })
    expect(next.calledOnce).to.equal(true)
    security.authenticatedUsers.remove(token)
  })

  it('does not recreate a revoked session from a still-valid JWT', () => {
    const user = { data: { id: 99001, role: security.roles.customer } as unknown as UserModel }
    const token = security.authorize(user)
    security.authenticatedUsers.put(token, user)
    security.authenticatedUsers.removeByUserId(user.data.id)

    const req = { cookies: { token }, headers: {} } as unknown as Request
    const res = { cookie: sinon.spy() } as any
    const next = sinon.spy()

    security.updateAuthenticatedUsers()(req, res, next)

    expect(security.authenticatedUsers.get(token)).to.equal(undefined)
    expect(res.cookie.called).to.equal(false)
    expect(next.calledOnce).to.equal(true)
  })

  it('does not grant an accounting role to a revoked token', () => {
    const user = { data: { id: 99002, role: security.roles.accounting } as unknown as UserModel }
    const token = security.authorize(user)
    security.authenticatedUsers.put(token, user)
    security.authenticatedUsers.removeByUserId(user.data.id)

    const req = { headers: { authorization: `Bearer ${token}` } } as unknown as Request
    const res = { status: sinon.stub().returnsThis(), json: sinon.spy() } as any
    const next = sinon.spy()

    security.isAccounting()(req, res, next)

    expect(next.called).to.equal(false)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('does not recognize revoked deluxe or customer tokens', () => {
    const deluxeUser = {
      data: {
        id: 99003,
        email: 'revoked-deluxe@juice-sh.op',
        role: security.roles.deluxe,
        deluxeToken: security.deluxeToken('revoked-deluxe@juice-sh.op')
      } as unknown as UserModel
    }
    const deluxeJwt = security.authorize(deluxeUser)
    security.authenticatedUsers.put(deluxeJwt, deluxeUser)
    security.authenticatedUsers.removeByUserId(deluxeUser.data.id)

    const customerUser = { data: { id: 99004, role: security.roles.customer } as unknown as UserModel }
    const customerJwt = security.authorize(customerUser)
    security.authenticatedUsers.put(customerJwt, customerUser)
    security.authenticatedUsers.removeByUserId(customerUser.data.id)

    expect(security.isDeluxe({ headers: { authorization: `Bearer ${deluxeJwt}` } } as unknown as Request)).to.equal(false)
    expect(security.isCustomer({ headers: { authorization: `Bearer ${customerJwt}` } } as unknown as Request)).to.equal(false)
  })

  it('revokes the active server session during the logout flow', async () => {
    const user = { data: { id: 99005, role: security.roles.customer } as unknown as UserModel }
    const token = security.authorize(user)
    security.authenticatedUsers.put(token, user)
    const update = sinon.stub().resolves({ id: user.data.id, email: 'logout@juice-sh.op', lastLoginIp: '127.0.0.1', profileImage: 'default.svg' })
    const findUser = sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
    const req = {
      headers: { authorization: `Bearer ${token}` },
      socket: { remoteAddress: '127.0.0.1' }
    } as unknown as Request
    const res = { json: sinon.spy() } as any

    try {
      await saveLoginIp()(req, res, sinon.spy())
      expect(security.authenticatedUsers.get(token)).to.equal(undefined)
      expect(res.json.calledOnce).to.equal(true)
    } finally {
      findUser.restore()
    }
  })

  it('still revokes the session when saving the logout IP fails', async () => {
    const user = { data: { id: 99006, role: security.roles.customer } as unknown as UserModel }
    const token = security.authorize(user)
    security.authenticatedUsers.put(token, user)
    const findUser = sinon.stub(UserModel, 'findByPk').rejects(new Error('database unavailable'))
    const req = {
      headers: { authorization: `Bearer ${token}` },
      socket: { remoteAddress: '127.0.0.1' }
    } as unknown as Request
    const next = sinon.spy()

    try {
      await saveLoginIp()(req, {} as any, next)
      expect(security.authenticatedUsers.get(token)).to.equal(undefined)
      expect(next.calledOnce).to.equal(true)
    } finally {
      findUser.restore()
    }
  })
})
