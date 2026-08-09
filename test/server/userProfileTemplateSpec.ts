/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import pug from 'pug'
import chai from 'chai'

const expect = chai.expect

describe('user profile template', () => {
  const template = fs.readFileSync('views/userProfile.pug', 'utf8')

  it('renders username template syntax and markup as escaped text', () => {
    const render = pug.compile(template)
    const username = '#{process.version}<script>alert(`xss`)</script>'
    const html = render({ username, profileImage: '/assets/public/images/uploads/default.svg' })

    expect(html).to.contain('#{process.version}&lt;script&gt;alert(`xss`)&lt;/script&gt;')
    expect(html).not.to.contain('<script>alert(`xss`)</script>')
  })
})
