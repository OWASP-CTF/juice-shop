/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { readFileSync } from 'fs'
import { expect } from 'chai'
import path from 'path'

describe('developer backup manifests', () => {
  it('do not request the compromised eslint-scope release', () => {
    const manifest = JSON.parse(readFileSync(path.resolve('ftp/package.json.bak'), 'utf8'))
    const lockfile = JSON.parse(readFileSync(path.resolve('ftp/package-lock.json.bak'), 'utf8'))
    const requestedVersion = manifest.devDependencies['eslint-scope']

    expect(requestedVersion).to.equal('3.7.3')
    expect(lockfile.packages[''].devDependencies['eslint-scope']).to.equal(requestedVersion)
    expect(lockfile.packages['node_modules/eslint-scope'].version).to.equal(requestedVersion)
  })
})
