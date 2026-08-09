/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as appRouting from './app.routing'

describe('app.routing', () => {
    it('no longer exports the obfuscated token-sale route matcher or its helper functions', () => {
        const exportedNames = Object.keys(appRouting)
        expect(exportedNames).not.toContain('tokenMatcher')
        expect(exportedNames).not.toContain('token1')
        expect(exportedNames).not.toContain('token2')
    })

    it('still exports the unrelated oauthMatcher used for the OAuth callback route', () => {
        expect(appRouting.oauthMatcher).toBeTypeOf('function')
    })

    it('still exports the compiled Routing module', () => {
        expect(appRouting.Routing).toBeTruthy()
    })
})
