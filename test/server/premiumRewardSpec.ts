/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import { servePremiumContent } from '../../routes/premiumReward'
import * as security from '../../lib/insecurity'

const expect = chai.expect
chai.use(sinonChai)

describe('premiumReward', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), json: sinon.spy() }
    res.status = sinon.stub().returns(res)
    const email = 'deluxe@juice-sh.op'
    const token = security.authorize({ data: { email, role: security.roles.deluxe, deluxeToken: security.deluxeToken(email) } })
    req = { headers: { authorization: `Bearer ${token}` } }
    save = () => ({
      then () { }
    })
  })

  it('should serve /frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg', () => {
    servePremiumContent()(req, res)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/frontend[/\\]dist[/\\]frontend[/\\]assets[/\\]private[/\\]JuiceShop_Wallpaper_1920x1080_VR\.jpg/))
  })

  it('should not solve "premiumPaywallChallenge" for an authorized request', () => {
    challenges.premiumPaywallChallenge = { solved: false, save } as unknown as Challenge

    servePremiumContent()(req, res)

    expect(challenges.premiumPaywallChallenge.solved).to.equal(false)
  })

  it('should reject users without a valid deluxe token', () => {
    req.headers = {}

    servePremiumContent()(req, res)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile.called).to.equal(false)
  })
})
