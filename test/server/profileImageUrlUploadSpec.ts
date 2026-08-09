/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'

import { fetchableProfileImageUrl } from '../../routes/profileImageUrlUpload'

const expect = chai.expect

describe('profileImageUrlUpload', () => {
  it('accepts a direct public HTTP address', async () => {
    const url = await fetchableProfileImageUrl('https://93.184.216.34/image.png')

    expect(url?.href).to.equal('https://93.184.216.34/image.png')
  })

  for (const url of [
    'http://localhost:3000/solve/challenges/server-side',
    'http://127.0.0.1/internal',
    'http://10.0.0.1/internal',
    'http://169.254.169.254/latest/meta-data',
    'http://[::1]/internal',
    'http://[::ffff:127.0.0.1]/internal'
  ]) {
    it(`rejects private destination ${url}`, async () => {
      expect(await fetchableProfileImageUrl(url)).to.equal(undefined)
    })
  }

  it('rejects non-HTTP protocols and embedded credentials', async () => {
    expect(await fetchableProfileImageUrl('file:///etc/passwd')).to.equal(undefined)
    expect(await fetchableProfileImageUrl('https://user:pass@93.184.216.34/image.png')).to.equal(undefined)
  })
})
