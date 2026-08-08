/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { ROUTES, UrlSegment, type Routes } from '@angular/router'

import { Routing, oauthMatcher } from './app.routing'

const routeProvider = Routing.providers
  ?.map(provider => provider as { provide?: unknown, useValue?: unknown })
  .find(provider => provider.provide === ROUTES)
const routes = routeProvider?.useValue as Routes

describe('application routes', () => {
  afterEach(() => {
    window.history.replaceState(null, '', '/')
  })

  it('does not register the unreleased token sale or development Web3 sandbox', () => {
    expect(routes.some(route => route.path === 'web3-sandbox')).toBe(false)
    expect(routes.some(route => route.path === 'tokensale-ico-ea')).toBe(false)
    expect(routes.filter(route => route.matcher).map(route => route.matcher)).toEqual([oauthMatcher])
  })

  it('keeps the scoreboard and Web3 wallet routes available', () => {
    expect(routes.some(route => route.path === 'score-board')).toBe(true)
    expect(routes.some(route => route.path === 'wallet-web3')).toBe(true)
  })

  it('keeps OAuth access-token URLs mapped through the OAuth matcher', () => {
    window.history.replaceState(null, '', '/#access_token=test-token')
    const segments = [new UrlSegment('oauth', {})]

    expect(oauthMatcher(segments)).toEqual({ consumed: segments })
  })
})
