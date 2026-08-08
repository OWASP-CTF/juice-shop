/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'

import { serializeSubtitles } from '../../routes/videoHandler'

const expect = chai.expect

describe('videoHandler', () => {
  it('serializes subtitle markup without creating an HTML script boundary', () => {
    const subtitles = 'WEBVTT\n\n00:00:00.000 --> 00:00:01.000\n</script><script>alert(1)</script>'
    const serialized = serializeSubtitles(subtitles)

    expect(serialized).not.to.contain('</script>')
    expect(JSON.parse(serialized)).to.equal(subtitles)
  })
})
